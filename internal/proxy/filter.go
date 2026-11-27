package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"gitlab.soraharu.com/XiaoXi/keycordon/internal/protocol"
	"gitlab.soraharu.com/XiaoXi/keycordon/internal/restore"
	"gitlab.soraharu.com/XiaoXi/keycordon/internal/rewrite"
	"gitlab.soraharu.com/XiaoXi/keycordon/internal/usage"
	"gitlab.soraharu.com/XiaoXi/keycordon/internal/vault"
)

type ctxKey struct{}

// reqState travels with a filtered request to the response handler.
type reqState struct {
	a        *protocol.Adapter
	caller   *vault.Caller
	res      rewrite.Result
	scanTime time.Duration
	start    time.Time
	restore  bool
}

// credential returns the first client credential, used only to derive the
// caller ID. Credentials are always forwarded unchanged.
func credential(r *http.Request) string {
	if v := r.Header.Get("Authorization"); v != "" {
		if len(v) > 7 && strings.EqualFold(v[:7], "bearer ") {
			return strings.TrimSpace(v[7:])
		}
		return v
	}
	for _, h := range []string{"X-Api-Key", "X-Goog-Api-Key", "Api-Key"} {
		if v := r.Header.Get(h); v != "" {
			return v
		}
	}
	q := r.URL.Query()
	for _, k := range []string{"key", "auth_token"} {
		if v := q.Get(k); v != "" {
			return v
		}
	}
	return ""
}

func (s *Server) filter(w http.ResponseWriter, r *http.Request, a *protocol.Adapter) {
	start := time.Now()
	callerID := "local"
	if cred := credential(r); cred != "" {
		callerID = s.vault.CallerID(cred)
	} else if !s.loopback && *s.cfg.Caller.RequireOnNonLoopback {
		writeError(w, http.StatusUnauthorized, "keycordon_no_credential", "a credential is required to identify the caller")
		return
	}
	c := s.vault.Caller(callerID)

	var raw []byte
	if r.Body != nil {
		var err error
		raw, err = io.ReadAll(http.MaxBytesReader(w, r.Body, s.cfg.Limits.MaxBodyBytes))
		r.Body.Close()
		if err != nil {
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				writeError(w, http.StatusRequestEntityTooLarge, "keycordon_body_too_large", "request body too large")
			} else {
				writeError(w, http.StatusBadRequest, "keycordon_bad_body", "failed to read request body")
			}
			return
		}
	}
	body, err := decodeBody(raw, r.Header.Values("Content-Encoding"), s.cfg.Limits.MaxDecodedBytes)
	switch {
	case errors.Is(err, errUnknownEncoding):
		writeError(w, http.StatusUnsupportedMediaType, "keycordon_unsupported_encoding", "unsupported Content-Encoding")
		return
	case errors.Is(err, errTooLarge):
		writeError(w, http.StatusRequestEntityTooLarge, "keycordon_body_too_large", "decoded request body too large")
		return
	case err != nil:
		writeError(w, http.StatusBadRequest, "keycordon_bad_encoding", "failed to decode request body")
		return
	}
	// read_ms covers receiving the body and undoing Content-Encoding; scan_ms
	// covers only detection and rewriting. Bundling them made scan_ms look
	// like scan time when it was mostly a gzip decompress of a 900 KB body.
	readTime := time.Since(start)

	ct := r.Header.Get("Content-Type")
	mt, _, _ := mime.ParseMediaType(ct)
	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.Limits.ScanTimeout)
	defer cancel()
	res := rewrite.Result{Body: body, Replaced: map[string]int{}, InjectReason: rewrite.InjectEmptyBody}
	switch {
	case len(bytes.TrimSpace(body)) == 0:
	case a.Multipart && mt == "multipart/form-data":
		res, err = s.rw.Multipart(ctx, a, body, ct, c)
	case mt == "" || mt == "application/json" || strings.HasSuffix(mt, "+json") || mt == "text/plain":
		res, err = s.rw.JSON(ctx, a, body, c)
	default:
		writeError(w, http.StatusUnsupportedMediaType, "keycordon_unsupported_content_type", "unsupported Content-Type for this AI endpoint")
		return
	}
	scanTime := time.Since(start) - readTime
	if err != nil {
		if errors.Is(err, rewrite.ErrBadRequest) {
			writeError(w, http.StatusBadRequest, "keycordon_bad_request", "request body is not valid for this AI endpoint")
			return
		}
		// Fail closed: an unscanned body is never forwarded.
		s.log.Error("scan failed; request blocked", "adapter", a.ID, "path", r.URL.Path, "error", err.Error())
		writeError(w, http.StatusServiceUnavailable, "keycordon_scan_failed", "secret scan failed; request was not forwarded")
		return
	}

	st := &reqState{a: a, caller: c, res: res, scanTime: scanTime, start: start}
	out := res.Body
	if s.cfg.Mode == "observe" {
		out = raw
	} else {
		r.Header.Del("Content-Encoding")
		// Let the transport negotiate gzip and decode it transparently so
		// the response can be restored.
		r.Header.Del("Accept-Encoding")
		st.restore = *s.cfg.Restore.Enabled && a.Restore && c.Len() > 0
	}
	r.Body = io.NopCloser(bytes.NewReader(out))
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(out)), nil }
	r.ContentLength = int64(len(out))
	r.Header.Set("Content-Length", strconv.Itoa(len(out)))
	// Units, Frozen and InjectReason are what makes a quiet log line
	// explainable: a request that replaced nothing still shows whether the
	// scan happened (units), how much of the history was answered from the
	// sent memo (frozen) and why the notice was or was not added.
	attrs := []any{
		"adapter", a.ID, "caller", shortID(callerID), "mode", s.cfg.Mode,
		"replaced", res.Count(), "rules", res.Replaced, "injected", res.Injected,
		"inject", res.InjectReason, "units", res.Units, "frozen", res.Frozen,
		"body_bytes", len(raw), "read_ms", readTime.Milliseconds(), "scan_ms", scanTime.Milliseconds(),
	}
	if worthInfo(s.cfg.Mode, res) {
		s.log.Info("request filtered", attrs...)
	} else {
		s.log.Debug("request filtered", attrs...)
	}
	s.filtered.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, st)))
}

// worthInfo decides whether a filtered request deserves a line at info
// level. A request that replaced nothing is normally quiet, but a notice
// that was deliberately not added is exactly what a user debugging
// "injected: false" needs to see.
func worthInfo(mode string, res rewrite.Result) bool {
	if res.Count() > 0 || mode == "observe" || res.Injected {
		return true
	}
	switch res.InjectReason {
	case rewrite.InjectPresent, rewrite.InjectServerState, rewrite.InjectNoPlace:
		return true
	}
	return false
}

func shortID(id string) string {
	if len(id) > 9 {
		return id[:9]
	}
	return id
}

func (s *Server) modifyResponse(resp *http.Response) error {
	st, _ := resp.Request.Context().Value(ctxKey{}).(*reqState)
	if st == nil || resp.Body == nil || resp.Body == http.NoBody {
		return nil
	}
	if s.cfg.Log.Usage {
		resp.Body = usage.Watch(resp.Body, func(i usage.Info) {
			if i.Empty() {
				return
			}
			attrs := []any{
				"caller", shortID(st.caller.ID()), "adapter", st.a.ID, "model", i.Model,
				"input_tokens", i.InputTokens, "cached_tokens", i.CachedTokens,
				"output_tokens", i.OutputTokens, "cache_hit", fmt.Sprintf("%.1f%%", 100*i.HitRate()),
			}
			if i.CacheWriteTokens > 0 {
				attrs = append(attrs, "cache_write_tokens", i.CacheWriteTokens)
			}
			s.log.Info("upstream usage", attrs...)
		})
	}
	if !st.restore {
		return nil
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" && !strings.EqualFold(enc, "identity") {
		s.log.Warn("compressed response cannot be restored; passed through", "adapter", st.a.ID, "encoding", enc)
		return nil
	}
	mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	a, c := st.a, st.caller
	switch {
	case mt == "text/event-stream":
		s.pipe(resp, resp.Body, func(w io.Writer) restore.Stream { return restore.NewSSE(a, c, w, nil) })
	case a.NDJSONStream && (strings.Contains(mt, "ndjson") || mt == "application/jsonl"):
		s.pipe(resp, resp.Body, func(w io.Writer) restore.Stream { return restore.NewNDJSON(a, c, w, nil) })
	case mt == "application/json" || strings.HasSuffix(mt, "+json") || mt == "":
		br := bufio.NewReaderSize(resp.Body, 4096)
		if a.JSONArrayStream && firstByte(br) == '[' {
			s.pipe(resp, readCloser{br, resp.Body}, func(w io.Writer) restore.Stream { return restore.NewJSONArray(a, c, w, nil) })
			return nil
		}
		s.buffered(resp, readCloser{br, resp.Body}, func(b []byte) []byte { return restore.JSON(a, c, b) })
	case strings.HasPrefix(mt, "text/"):
		s.buffered(resp, resp.Body, func(b []byte) []byte { return restore.Bytes(c, b) })
	}
	return nil
}

type readCloser struct {
	io.Reader
	io.Closer
}

func firstByte(br *bufio.Reader) byte {
	for n := 1; n <= 64; n++ {
		b, err := br.Peek(n)
		if len(b) < n {
			return 0
		}
		if c := b[n-1]; c != ' ' && c != '\n' && c != '\r' && c != '\t' {
			return c
		}
		if err != nil {
			return 0
		}
	}
	return 0
}

// pipe streams the body through a restorer. Errors fail open only in the
// sense that unrestorable data is forwarded as is.
func (s *Server) pipe(resp *http.Response, src io.ReadCloser, mk func(io.Writer) restore.Stream) {
	pr, pw := io.Pipe()
	go func() {
		st := mk(pw)
		_, err := io.Copy(st, src)
		cerr := st.Close()
		src.Close()
		if err == nil {
			err = cerr
		}
		pw.CloseWithError(err)
	}()
	resp.Body = pr
	resp.ContentLength = -1
	resp.Header.Del("Content-Length")
}

// buffered restores a complete body. Bodies over the limit are forwarded
// unchanged.
func (s *Server) buffered(resp *http.Response, src io.ReadCloser, fn func([]byte) []byte) {
	limit := s.cfg.Limits.MaxResponseBytes
	data, err := io.ReadAll(io.LimitReader(src, limit+1))
	if err != nil || int64(len(data)) > limit {
		if int64(len(data)) > limit {
			s.log.Warn("response too large to restore; passed through", "limit", limit)
		}
		resp.Body = readCloser{io.MultiReader(bytes.NewReader(data), src), src}
		return
	}
	src.Close()
	out := fn(data)
	resp.Body = io.NopCloser(bytes.NewReader(out))
	resp.ContentLength = int64(len(out))
	resp.Header.Set("Content-Length", strconv.Itoa(len(out)))
}

func errorsAs(err error, target any) bool { return errors.As(err, target) }

// redactErr removes URLs (which may carry ?key=) from transport errors.
func redactErr(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		u, perr := url.Parse(ue.URL)
		if perr == nil {
			u.RawQuery = ""
			u.User = nil
			return ue.Op + " " + u.String() + ": " + ue.Err.Error()
		}
		return ue.Op + ": " + ue.Err.Error()
	}
	return err.Error()
}
