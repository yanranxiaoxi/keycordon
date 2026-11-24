// Package proxy is the HTTP reverse proxy. Requests to registered AI
// endpoints go through the filter pipeline; everything else is forwarded
// untouched by a plain httputil.ReverseProxy.
package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"gitlab.soraharu.com/XiaoXi/keycordon/internal/config"
	"gitlab.soraharu.com/XiaoXi/keycordon/internal/detector"
	"gitlab.soraharu.com/XiaoXi/keycordon/internal/protocol"
	"gitlab.soraharu.com/XiaoXi/keycordon/internal/rewrite"
	"gitlab.soraharu.com/XiaoXi/keycordon/internal/vault"
)

// HealthPath is served by keycordon itself; it is namespaced so it never
// shadows an upstream /healthz.
const HealthPath = "/_keycordon/healthz"

// Options holds the dependencies of a Server.
type Options struct {
	Config    *config.Config
	Registry  *protocol.Registry
	Detector  *detector.Detector
	Vault     *vault.Vault
	KeyFP     string
	Version   string
	Logger    *slog.Logger
	Transport http.RoundTripper
}

// Server implements http.Handler.
type Server struct {
	cfg      *config.Config
	reg      *protocol.Registry
	det      *detector.Detector
	vault    *vault.Vault
	rw       *rewrite.Rewriter
	log      *slog.Logger
	target   *url.URL
	pass     *httputil.ReverseProxy
	filtered *httputil.ReverseProxy
	loopback bool
	keyFP    string
	version  string
}

// New builds a Server.
func New(o Options) (*Server, error) {
	target, err := url.Parse(o.Config.Upstream)
	if err != nil {
		return nil, err
	}
	log := o.Logger
	if log == nil {
		log = slog.Default()
	}
	tr := o.Transport
	if tr == nil {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.ResponseHeaderTimeout = 0
		if o.Config.InsecureSkipVerify {
			t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // explicit opt-in
			log.Warn("TLS certificate verification of the upstream is disabled")
		}
		tr = t
	}
	s := &Server{
		cfg:   o.Config,
		reg:   o.Registry,
		det:   o.Detector,
		vault: o.Vault,
		rw: &rewrite.Rewriter{
			Detector:     o.Detector,
			MaxDepth:     o.Config.Limits.MaxJSONDepth,
			Inject:       *o.Config.Request.InjectInstruction,
			InjectAlways: *o.Config.Request.InjectAlways,
			MinLength:    o.Config.Detector.MinValueLength,
			Sent:         vault.NewSent(o.Config.Vault.MaxSentTexts),
			Upstream:     o.Config.Upstream,
		},
		log:      log,
		target:   target,
		loopback: o.Config.ListenIsLoopback(),
		keyFP:    o.KeyFP,
		version:  o.Version,
	}
	rewriteFn := func(pr *httputil.ProxyRequest) {
		pr.SetURL(target)
		if s.cfg.PreserveHost {
			pr.Out.Host = pr.In.Host
		}
	}
	s.pass = &httputil.ReverseProxy{
		Rewrite:       rewriteFn,
		Transport:     tr,
		FlushInterval: -1,
		ErrorHandler:  s.upstreamError,
		ErrorLog:      slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	s.filtered = &httputil.ReverseProxy{
		Rewrite:        rewriteFn,
		Transport:      tr,
		FlushInterval:  -1,
		ModifyResponse: s.modifyResponse,
		ErrorHandler:   s.upstreamError,
		ErrorLog:       slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	return s, nil
}

// Run sweeps idle vault entries until ctx is done.
func (s *Server) Run(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.vault.Sweep()
		}
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if v := recover(); v != nil {
			if v == http.ErrAbortHandler {
				panic(v)
			}
			// The panic value may contain request data; only its type is logged.
			s.log.Error("panic while handling request", "path", r.URL.Path, "panic_type", typeName(v))
			writeError(w, http.StatusInternalServerError, "internal_error", "keycordon internal error")
		}
	}()
	if r.URL.Path == HealthPath && r.Method == http.MethodGet {
		s.health(w)
		return
	}
	upgrade := isUpgrade(r)
	a := s.reg.Match(r.Method, r.URL.Path, upgrade)
	switch {
	case a == nil:
		s.passthrough(w, r)
	case a.Filter == protocol.FilterUnsupported:
		s.unsupported(w, r, a, http.StatusNotImplemented)
	case upgrade:
		s.unsupported(w, r, a, http.StatusUpgradeRequired)
	default:
		s.filter(w, r, a)
	}
}

func typeName(v any) string {
	switch v.(type) {
	case error:
		return "error"
	case string:
		return "string"
	}
	return "other"
}

func isUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") && r.Header.Get("Upgrade") != ""
}

func (s *Server) unsupported(w http.ResponseWriter, r *http.Request, a *protocol.Adapter, status int) {
	if s.cfg.Protocols.UnsupportedPolicy == "passthrough" {
		s.log.Warn("unfiltered AI traffic passed through", "adapter", a.ID, "method", r.Method, "path", r.URL.Path)
		s.pass.ServeHTTP(w, r)
		return
	}
	s.log.Info("unsupported AI transport rejected", "adapter", a.ID, "method", r.Method, "path", r.URL.Path)
	writeError(w, status, "keycordon_unsupported", "keycordon cannot filter this AI transport (WebSocket/realtime); use the HTTP API")
}

// passthrough forwards a request untouched. When enabled, the first 4 KiB of
// POST JSON bodies are inspected to warn about unregistered AI endpoints;
// nothing is changed or blocked.
func (s *Server) passthrough(w http.ResponseWriter, r *http.Request) {
	var probe *prefixRecorder
	if *s.cfg.Protocols.DetectUnregistered && r.Method == http.MethodPost && r.Body != nil &&
		strings.Contains(r.Header.Get("Content-Type"), "json") && r.Header.Get("Content-Encoding") == "" {
		probe = &prefixRecorder{rc: r.Body}
		r.Body = probe
	}
	s.pass.ServeHTTP(w, r)
	if probe != nil && looksLikeAIRequest(probe.buf.Bytes()) {
		s.log.Warn("unregistered_ai_endpoint: request looks like AI traffic but was not filtered",
			"method", r.Method, "path", r.URL.Path)
	}
}

type prefixRecorder struct {
	rc interface {
		Read([]byte) (int, error)
		Close() error
	}
	buf bytes.Buffer
}

func (p *prefixRecorder) Read(b []byte) (int, error) {
	n, err := p.rc.Read(b)
	if room := 4096 - p.buf.Len(); room > 0 && n > 0 {
		p.buf.Write(b[:min(n, room)])
	}
	return n, err
}

func (p *prefixRecorder) Close() error { return p.rc.Close() }

func looksLikeAIRequest(b []byte) bool {
	for _, k := range []string{`"messages"`, `"contents"`, `"input"`, `"prompt"`, `"instructions"`} {
		if bytes.Contains(b, []byte(k)) {
			return true
		}
	}
	return false
}

func (s *Server) health(w http.ResponseWriter) {
	callers, entries := s.vault.Stats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":                 "ok",
		"version":                s.version,
		"mode":                   s.cfg.Mode,
		"master_key_fingerprint": s.keyFP,
		"rules_hash":             s.det.RulesHash(),
		"adapters":               len(s.reg.Adapters()),
		"callers":                callers,
		"secrets":                entries,
	})
}

func (s *Server) upstreamError(w http.ResponseWriter, r *http.Request, err error) {
	if r.Context().Err() != nil {
		return
	}
	var ne net.Error
	msg := "upstream unavailable"
	if errorsAs(err, &ne) && ne.Timeout() {
		msg = "upstream timeout"
	}
	s.log.Warn("upstream error", "method", r.Method, "path", r.URL.Path, "error", redactErr(err))
	writeError(w, http.StatusBadGateway, "keycordon_upstream_error", msg)
}

// writeError replies with an OpenAI-style error object. It never echoes
// request content.
func writeError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Keycordon-Error", code)
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{"type": code, "code": code, "message": msg},
	})
}
