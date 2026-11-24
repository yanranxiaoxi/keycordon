package proxy

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/klauspost/compress/zstd"

	"gitlab.soraharu.com/XiaoXi/keycordon/internal/config"
	"gitlab.soraharu.com/XiaoXi/keycordon/internal/detector"
	"gitlab.soraharu.com/XiaoXi/keycordon/internal/protocol"
	"gitlab.soraharu.com/XiaoXi/keycordon/internal/vault"
)

const ghToken = "ghp_NqVwYS81VP7Hb1DX8pQ2mZ7xL4kR9tWcB3vE"

var phRe = regexp.MustCompile(`<SECRET_[A-Z0-9_]+_[0-9a-f]{8,}>`)

var (
	once sync.Once
	det  *detector.Detector
	reg  *protocol.Registry
)

// upstream records the last request and answers with handler.
type upstream struct {
	mu      sync.Mutex
	body    []byte
	header  http.Header
	url     string
	handler func(w http.ResponseWriter, r *http.Request, body []byte)
}

func (u *upstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	u.mu.Lock()
	u.body, u.header, u.url = b, r.Header.Clone(), r.URL.String()
	h := u.handler
	u.mu.Unlock()
	if h != nil {
		h(w, r, b)
	}
}

func newProxy(t *testing.T, mutate func(*config.Config)) (*httptest.Server, *upstream) {
	t.Helper()
	once.Do(func() {
		var err error
		if det, err = detector.New(detector.Options{MaxDecodeDepth: 2}); err != nil {
			panic(err)
		}
		if reg, err = protocol.Load(protocol.Options{}); err != nil {
			panic(err)
		}
	})
	up := &upstream{}
	us := httptest.NewServer(up)
	t.Cleanup(us.Close)
	cfg := config.Default()
	cfg.Upstream = us.URL + "/base"
	if mutate != nil {
		mutate(cfg)
	}
	srv, err := New(Options{
		Config: cfg, Registry: reg, Detector: det,
		Vault:  vault.New([]byte("0123456789abcdef0123456789abcdef"), vault.Options{}),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	ps := httptest.NewServer(srv)
	t.Cleanup(ps.Close)
	return ps, up
}

func do(t *testing.T, method, url string, body []byte, hdr map[string]string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, url, bytes.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	tr := &http.Transport{DisableCompression: true}
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, b
}

func gz(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

func TestPassthroughUntouched(t *testing.T) {
	ps, up := newProxy(t, nil)
	reqBody := gz([]byte(`{"messages":[{"role":"user","content":"` + ghToken + `"}]}`))
	respBody := gz([]byte("binary-ish " + ghToken))
	up.handler = func(w http.ResponseWriter, r *http.Request, _ []byte) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(respBody)
	}
	resp, got := do(t, "POST", ps.URL+"/v1/files?key=abc", reqBody, map[string]string{
		"Content-Encoding": "gzip", "Accept-Encoding": "gzip", "Content-Type": "application/json", "X-Custom": "1",
	})
	if !bytes.Equal(up.body, reqBody) {
		t.Fatal("passthrough request body changed")
	}
	if up.header.Get("Accept-Encoding") != "gzip" || up.header.Get("X-Custom") != "1" || up.header.Get("X-Forwarded-For") != "" {
		t.Fatalf("passthrough headers changed: %v", up.header)
	}
	if up.url != "/base/v1/files?key=abc" {
		t.Fatalf("url %s", up.url)
	}
	if !bytes.Equal(got, respBody) || resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatal("passthrough response changed")
	}
}

func TestChatRoundTripSSE(t *testing.T) {
	ps, up := newProxy(t, nil)
	up.handler = func(w http.ResponseWriter, r *http.Request, body []byte) {
		ph := phRe.FindString(string(body))
		w.Header().Set("Content-Type", "text/event-stream")
		half := len(ph) / 2
		for _, part := range []string{"token: " + ph[:half], ph[half:] + " done"} {
			b, _ := json.Marshal(part)
			io.WriteString(w, `data: {"choices":[{"index":0,"delta":{"content":`+string(b)+`}}]}`+"\n\n")
			w.(http.Flusher).Flush()
		}
		io.WriteString(w, "data: [DONE]\n\n")
	}
	body := gz([]byte(`{"model":"gpt-5","stream":true,"messages":[{"role":"user","content":"use ` + ghToken + `"}]}`))
	resp, got := do(t, "POST", ps.URL+"/v1/chat/completions", body, map[string]string{
		"Content-Encoding": "gzip", "Authorization": "Bearer sk-client-a", "Content-Type": "application/json",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, got)
	}
	if bytes.Contains(up.body, []byte(ghToken)) || !phRe.Match(up.body) {
		t.Fatalf("upstream saw the secret or no placeholder: %s", up.body)
	}
	if up.header.Get("Content-Encoding") != "" || up.header.Get("Authorization") != "Bearer sk-client-a" {
		t.Fatalf("headers: %v", up.header)
	}
	if !strings.Contains(string(up.body), "[keycordon/1]") {
		t.Fatal("notice not injected")
	}
	var text string
	for _, ev := range strings.Split(string(got), "\n\n") {
		d, ok := strings.CutPrefix(ev, "data: ")
		if !ok || d == "[DONE]" {
			continue
		}
		var v struct {
			Choices []struct{ Delta struct{ Content string } }
		}
		json.Unmarshal([]byte(d), &v)
		text += v.Choices[0].Delta.Content
	}
	if text != "token: "+ghToken+" done" {
		t.Fatalf("restored text %q\n%s", text, got)
	}
}

func TestCallerIsolation(t *testing.T) {
	ps, up := newProxy(t, nil)
	var seen string
	up.handler = func(w http.ResponseWriter, r *http.Request, body []byte) {
		if p := phRe.FindString(string(body)); p != "" && seen == "" {
			seen = p
		}
		w.Header().Set("Content-Type", "application/json")
		b, _ := json.Marshal(seen)
		io.WriteString(w, `{"content":[{"type":"text","text":`+string(b)+`}]}`)
	}
	_, got := do(t, "POST", ps.URL+"/v1/messages", []byte(`{"messages":[{"role":"user","content":"`+ghToken+`"}]}`), map[string]string{"x-api-key": "client-a"})
	if !strings.Contains(string(got), ghToken) {
		t.Fatalf("owner should get the secret back: %s", got)
	}
	// Caller B replays A's placeholder hoping the proxy restores it.
	_, got = do(t, "POST", ps.URL+"/v1/messages", []byte(`{"messages":[{"role":"user","content":"`+seen+`"}]}`), map[string]string{"x-api-key": "client-b"})
	if strings.Contains(string(got), ghToken) {
		t.Fatal("caller B obtained caller A's secret")
	}
}

func TestEncodings(t *testing.T) {
	ps, up := newProxy(t, nil)
	up.handler = func(w http.ResponseWriter, r *http.Request, body []byte) { w.Write([]byte("{}")) }
	enc, _ := zstd.NewWriter(nil)
	zbody := enc.EncodeAll([]byte(`{"messages":[{"role":"user","content":"`+ghToken+`"}]}`), nil)
	resp, _ := do(t, "POST", ps.URL+"/v1/chat/completions", zbody, map[string]string{"Content-Encoding": "zstd"})
	if resp.StatusCode != 200 || bytes.Contains(up.body, []byte(ghToken)) {
		t.Fatalf("zstd body not scanned: %d %s", resp.StatusCode, up.body)
	}
	resp, _ = do(t, "POST", ps.URL+"/v1/chat/completions", []byte("xx"), map[string]string{"Content-Encoding": "compress"})
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("unknown encoding: %d", resp.StatusCode)
	}
	resp, _ = do(t, "POST", ps.URL+"/v1/chat/completions", []byte("{bad"), nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad json: %d", resp.StatusCode)
	}
	resp, _ = do(t, "POST", ps.URL+"/v1/chat/completions", []byte(strings.Repeat("[", 2000)), nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("deep json: %d", resp.StatusCode)
	}
	resp, _ = do(t, "POST", ps.URL+"/v1/chat/completions", []byte("<xml/>"), map[string]string{"Content-Type": "application/xml"})
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("xml: %d", resp.StatusCode)
	}
}

func TestBodyLimit(t *testing.T) {
	ps, _ := newProxy(t, func(c *config.Config) { c.Limits.MaxBodyBytes = 100; c.Limits.MaxDecodedBytes = 200 })
	resp, _ := do(t, "POST", ps.URL+"/v1/chat/completions", bytes.Repeat([]byte(" "), 101), nil)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("raw limit: %d", resp.StatusCode)
	}
	bomb := gz(bytes.Repeat([]byte(" "), 10000))
	resp, _ = do(t, "POST", ps.URL+"/v1/chat/completions", bomb, map[string]string{"Content-Encoding": "gzip"})
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("decoded limit: %d", resp.StatusCode)
	}
}

func TestNonLoopbackRequiresCredential(t *testing.T) {
	ps, _ := newProxy(t, func(c *config.Config) { c.Listen = "0.0.0.0:8318" })
	resp, _ := do(t, "POST", ps.URL+"/v1/chat/completions", []byte(`{"messages":[]}`), nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d", resp.StatusCode)
	}
	// Unregistered endpoints are still passed through.
	resp, _ = do(t, "GET", ps.URL+"/v1/models", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("models: %d", resp.StatusCode)
	}
}

func TestUnsupported(t *testing.T) {
	ps, _ := newProxy(t, nil)
	resp, _ := do(t, "GET", ps.URL+"/v1/responses", nil, map[string]string{"Connection": "Upgrade", "Upgrade": "websocket"})
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("ws: %d", resp.StatusCode)
	}
	resp, _ = do(t, "POST", ps.URL+"/v1/realtime/sessions", []byte(`{}`), nil)
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("realtime: %d", resp.StatusCode)
	}
	ps2, _ := newProxy(t, func(c *config.Config) { c.Protocols.UnsupportedPolicy = "passthrough" })
	resp, _ = do(t, "POST", ps2.URL+"/v1/realtime/sessions", []byte(`{}`), nil)
	if resp.StatusCode != 200 {
		t.Fatalf("passthrough policy: %d", resp.StatusCode)
	}
}

func TestGeminiKeyQueryAndArrayStream(t *testing.T) {
	ps, up := newProxy(t, func(c *config.Config) { c.Listen = "0.0.0.0:1" })
	up.handler = func(w http.ResponseWriter, r *http.Request, body []byte) {
		ph := phRe.FindString(string(body))
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `[{"candidates":[{"index":0,"content":{"parts":[{"text":"a`+ph[:6]+`"}]}}]}`+",\r\n")
		w.(http.Flusher).Flush()
		io.WriteString(w, `{"candidates":[{"index":0,"content":{"parts":[{"text":"`+ph[6:]+`b"}]}}]}]`)
	}
	resp, got := do(t, "POST", ps.URL+"/v1beta/models/gemini-2.5-pro:streamGenerateContent?key=goog-key",
		[]byte(`{"contents":[{"role":"user","parts":[{"text":"`+ghToken+`"}]}]}`), nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d %s", resp.StatusCode, got)
	}
	if !strings.Contains(up.url, "key=goog-key") || bytes.Contains(up.body, []byte(ghToken)) {
		t.Fatal("query key must be forwarded and body scanned")
	}
	if !bytes.Contains(up.body, []byte(`"systemInstruction":{"parts":[{"text":"[keycordon/1]`)) {
		t.Fatalf("gemini notice missing: %s", up.body)
	}
	var arr []struct {
		Candidates []struct {
			Content struct{ Parts []struct{ Text string } }
		}
	}
	if err := json.Unmarshal(got, &arr); err != nil {
		t.Fatalf("%v: %s", err, got)
	}
	if arr[0].Candidates[0].Content.Parts[0].Text+arr[1].Candidates[0].Content.Parts[0].Text != "a"+ghToken+"b" {
		t.Fatalf("not restored: %s", got)
	}
}

func TestObserveMode(t *testing.T) {
	ps, up := newProxy(t, func(c *config.Config) { c.Mode = "observe" })
	body := []byte(`{"messages":[{"role":"user","content":"` + ghToken + `"}]}`)
	do(t, "POST", ps.URL+"/v1/chat/completions", body, nil)
	if !bytes.Equal(up.body, body) {
		t.Fatal("observe mode must forward the original body")
	}
}

func TestHealth(t *testing.T) {
	ps, _ := newProxy(t, nil)
	resp, got := do(t, "GET", ps.URL+HealthPath, nil, nil)
	if resp.StatusCode != 200 || !strings.Contains(string(got), `"status":"ok"`) {
		t.Fatalf("%d %s", resp.StatusCode, got)
	}
}

func TestCredential(t *testing.T) {
	r := httptest.NewRequest("POST", "/x?key=q", nil)
	if credential(r) != "q" {
		t.Fatal("query key")
	}
	r.Header.Set("x-goog-api-key", "g")
	if credential(r) != "g" {
		t.Fatal("goog header")
	}
	r.Header.Set("Authorization", "Bearer  tok ")
	if credential(r) != "tok" {
		t.Fatal("bearer")
	}
	r.Header.Set("Authorization", "abc")
	if credential(r) != "abc" {
		t.Fatal("short authorization must not panic")
	}
}
