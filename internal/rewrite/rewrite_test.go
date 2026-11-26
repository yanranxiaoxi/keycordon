package rewrite

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"mime/multipart"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"gitlab.soraharu.com/XiaoXi/keycordon/internal/detector"
	"gitlab.soraharu.com/XiaoXi/keycordon/internal/protocol"
	"gitlab.soraharu.com/XiaoXi/keycordon/internal/vault"
)

const (
	ghToken  = "ghp_NqVwYS81VP7Hb1DX8pQ2mZ7xL4kR9tWcB3vE"
	awsKey   = "AKIAQX2LMNB7RT5KJW3P"
	bareTok  = "Zx8Kq2Lm9Pw4Rt7Yv3Bn6Hs1Jd5Gf0Ac"
	master32 = "0123456789abcdef0123456789abcdef"
)

var (
	setupOnce sync.Once
	det       *detector.Detector
	reg       *protocol.Registry
	// phRe matches a real placeholder; the notice's example
	// "<SECRET_TYPE_xxxxxxxx>" is not one.
	phRe = regexp.MustCompile(`<SECRET_[A-Z0-9_]+_[0-9a-f]{8,}>`)
)

func setup(t testing.TB) {
	t.Helper()
	setupOnce.Do(func() {
		var err error
		if det, err = detector.New(detector.Options{MaxDecodeDepth: 2}); err != nil {
			panic(err)
		}
		if reg, err = protocol.Load(protocol.Options{}); err != nil {
			panic(err)
		}
	})
}

func adapter(t testing.TB, path string) *protocol.Adapter {
	setup(t)
	a := reg.Match("POST", path, false)
	if a == nil {
		t.Fatalf("no adapter for %s", path)
	}
	return a
}

func newRW(inject bool) *Rewriter {
	return &Rewriter{Detector: det, Inject: inject, InjectAlways: inject, Sent: vault.NewSent(0), Upstream: "test"}
}

func caller() *vault.Caller {
	return vault.New([]byte(master32), vault.Options{}).Caller("local")
}

func mustValidJSON(t *testing.T, b []byte) {
	t.Helper()
	if !json.Valid(b) {
		t.Fatalf("invalid JSON output: %s", b)
	}
}

func TestNoSecretIsByteIdentical(t *testing.T) {
	a := adapter(t, "/v1/chat/completions")
	raw := []byte("{\n  \"model\": \"gpt-5\",\"messages\":[{\"role\":\"user\",\"content\":\"hello \\u00e9 world \\/ 1e6\"}],\n \"temperature\": 1.0e0 }")
	res, err := newRW(false).JSON(context.Background(), a, raw, caller())
	if err != nil {
		t.Fatal(err)
	}
	if &res.Body[0] != &raw[0] || res.Count() != 0 {
		t.Fatal("unchanged body must be forwarded as the same bytes")
	}
}

func TestChatReplaceAndRestoreShape(t *testing.T) {
	a := adapter(t, "/v1/chat/completions")
	args, _ := json.Marshal(map[string]any{"cmd": "curl -H 'Authorization: token " + ghToken + "' https://api.github.com", "id": awsKey})
	body := map[string]any{
		"model": "gpt-5",
		"messages": []any{
			map[string]any{"role": "system", "content": "You are helpful."},
			map[string]any{"role": "user", "content": "my key is " + ghToken + " and AWS " + awsKey},
			map[string]any{"role": "assistant", "tool_calls": []any{map[string]any{
				"id": "call_8fKq2Lm9Pw4Rt7Yv3Bn6Hs", "type": "function",
				"function": map[string]any{"name": "shell", "arguments": string(args)},
			}}},
		},
	}
	raw, _ := json.MarshalIndent(body, "", "  ")
	c := caller()
	res, err := newRW(true).JSON(context.Background(), a, raw, c)
	if err != nil {
		t.Fatal(err)
	}
	mustValidJSON(t, res.Body)
	out := string(res.Body)
	if strings.Contains(out, ghToken) || strings.Contains(out, awsKey) {
		t.Fatalf("secret leaked:\n%s", out)
	}
	if !res.Injected || !strings.Contains(out, `"You are helpful.\n\n`+InstructionMarker) {
		t.Fatalf("instruction not appended to system message:\n%s", out)
	}
	if !strings.Contains(out, "call_8fKq2Lm9Pw4Rt7Yv3Bn6Hs") {
		t.Fatal("frozen tool call id changed")
	}
	var parsed struct {
		Messages []struct {
			ToolCalls []struct {
				Function struct{ Arguments string }
			} `json:"tool_calls"`
		}
	}
	json.Unmarshal(res.Body, &parsed)
	var inner map[string]string
	if err := json.Unmarshal([]byte(parsed.Messages[2].ToolCalls[0].Function.Arguments), &inner); err != nil {
		t.Fatalf("tool arguments no longer valid JSON: %v", err)
	}
	ph := c.Placeholder(ghToken)
	if !strings.Contains(inner["cmd"], ph) || inner["id"] != c.Placeholder(awsKey) {
		t.Fatalf("inner JSON not rewritten: %v", inner)
	}
	if res.Count() < 4 {
		t.Fatalf("expected 4 replacements, got %v", res.Replaced)
	}
	// Bytes outside replaced strings are untouched (indentation kept).
	if !strings.HasPrefix(out, "{\n  \"messages\": [\n    {\n      \"content\": ") {
		t.Fatalf("layout changed:\n%s", out[:80])
	}
}

func TestDeterministicAcrossRestarts(t *testing.T) {
	a := adapter(t, "/v1/messages")
	raw := []byte(`{"model":"claude","system":[{"type":"text","text":"sys","cache_control":{"type":"ephemeral"}}],"messages":[{"role":"user","content":"token ` + bareTok + `"}]}`)
	r1, err := newRW(true).JSON(context.Background(), a, raw, caller())
	if err != nil {
		t.Fatal(err)
	}
	r2, _ := newRW(true).JSON(context.Background(), a, raw, caller())
	if !bytes.Equal(r1.Body, r2.Body) {
		t.Fatalf("output differs between vault instances:\n%s\n%s", r1.Body, r2.Body)
	}
	mustValidJSON(t, r1.Body)
	if !strings.Contains(string(r1.Body), `"cache_control":{"type":"ephemeral"}},{"type":"text","text":"`+InstructionMarker) {
		t.Fatalf("notice must be appended after existing system blocks:\n%s", r1.Body)
	}
}

func TestPrefixStableOverTurns(t *testing.T) {
	a := adapter(t, "/v1/chat/completions")
	c := caller()
	rw := newRW(true)
	msgs := []map[string]string{{"role": "user", "content": "deploy with GITHUB_TOKEN=" + ghToken}}
	var prev []byte
	for turn := 0; turn < 3; turn++ {
		raw, _ := json.Marshal(struct {
			Model    string              `json:"model"`
			Messages []map[string]string `json:"messages"`
		}{"m", msgs})
		res, err := rw.JSON(context.Background(), a, raw, c)
		if err != nil {
			t.Fatal(err)
		}
		if prev != nil {
			// Everything except the closing "]}" of the previous request must be a prefix.
			p := prev[:len(prev)-2]
			if !bytes.HasPrefix(res.Body, p) {
				t.Fatalf("turn %d broke the prefix:\nprev %s\ncur  %s", turn, prev, res.Body)
			}
		}
		prev = res.Body
		// The client sees restored text, so history carries the plaintext
		// again, now in a context the detector does not recognise.
		msgs = append(msgs,
			map[string]string{"role": "assistant", "content": "ran: curl -u x:" + ghToken},
			map[string]string{"role": "user", "content": "again"})
	}
	if strings.Contains(string(prev), ghToken) {
		t.Fatal("known secret leaked in later turn")
	}
}

func TestKnownSecretInUnrecognisedContext(t *testing.T) {
	a := adapter(t, "/v1/chat/completions")
	c := caller()
	weak := "hunter2-but-longer"
	c.Placeholder(weak)
	raw := []byte(`{"model":"m","messages":[{"role":"user","content":"the word is hunter2-but-longer ok"}]}`)
	res, err := newRW(false).JSON(context.Background(), a, raw, c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(res.Body), weak) || res.Replaced["known"] != 1 {
		t.Fatalf("known secret not replaced: %s %v", res.Body, res.Replaced)
	}
}

func TestFrozenAndPayload(t *testing.T) {
	a := adapter(t, "/v1/messages")
	raw := []byte(`{"model":"claude","messages":[{"role":"assistant","content":[` +
		`{"type":"thinking","thinking":"key ` + ghToken + `","signature":"sig"},` +
		`{"type":"tool_use","id":"toolu_01","name":"x","input":{"name":"` + ghToken + `","id":"` + awsKey + `"}}]}]}`)
	res, err := newRW(false).JSON(context.Background(), a, raw, caller())
	if err != nil {
		t.Fatal(err)
	}
	out := string(res.Body)
	if !strings.Contains(out, `"thinking":"key `+ghToken+`"`) {
		t.Fatal("signed thinking must stay frozen")
	}
	if strings.Contains(out, `"name":"`+ghToken) || strings.Contains(out, awsKey) {
		t.Fatalf("tool input keys named name/id must be scanned:\n%s", out)
	}
}

func TestDuplicateKeysDisableExemptions(t *testing.T) {
	a := adapter(t, "/v1/chat/completions")
	raw := []byte(`{"model":"` + ghToken + `","model":"gpt","messages":[]}`)
	res, err := newRW(false).JSON(context.Background(), a, raw, caller())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(res.Body), ghToken) {
		t.Fatal("duplicate keys must not allow frozen bypass")
	}
}

func TestInjectionTargets(t *testing.T) {
	cases := []struct {
		path, body, want string
	}{
		{"/v1/chat/completions", `{"messages":[{"role":"user","content":"hi"}]}`, `{"messages":[{"role":"system","content":"` + InstructionMarker},
		{"/v1/chat/completions", `{"messages":[{"role":"developer","content":[{"type":"text","text":"d"}]}]}`, `"text":"d"},{"type":"text","text":"` + InstructionMarker},
		{"/v1/messages", `{"messages":[]}`, `{"system":"` + InstructionMarker},
		{"/v1/messages", `{"system":"s","messages":[]}`, `{"system":"s\n\n` + InstructionMarker},
		{"/v1/responses", `{"input":[{"role":"user","content":"x"}]}`, `{"input":[{"type":"message","role":"developer","content":[{"type":"input_text","text":"` + InstructionMarker},
		{"/v1/responses", `{"input":"x","instructions":null}`, `"instructions":"` + InstructionMarker},
		{"/v1beta/models/g:generateContent", `{"contents":[]}`, `{"systemInstruction":{"parts":[{"text":"` + InstructionMarker},
		{"/v1beta/models/g:generateContent", `{"system_instruction":{"parts":[{"text":"a"}]},"contents":[]}`, `{"text":"a"},{"text":"` + InstructionMarker},
		{"/v1internal:generateContent", `{"model":"g","request":{"contents":[]}}`, `"request":{"systemInstruction":{"parts":[{"text":"` + InstructionMarker},
	}
	for _, tc := range cases {
		a := adapter(t, tc.path)
		res, err := newRW(true).JSON(context.Background(), a, []byte(tc.body), caller())
		if err != nil {
			t.Fatal(err)
		}
		mustValidJSON(t, res.Body)
		if !res.Injected || !strings.Contains(string(res.Body), tc.want) {
			t.Errorf("%s %s:\n got %s\nwant substring %s", tc.path, tc.body, res.Body, tc.want)
		}
		again, _ := newRW(true).JSON(context.Background(), a, res.Body, caller())
		if again.Injected {
			t.Errorf("%s: notice injected twice", tc.path)
		}
	}
	a := adapter(t, "/v1/responses")
	res, _ := newRW(true).JSON(context.Background(), a, []byte(`{"previous_response_id":"resp_1","input":[]}`), caller())
	if res.Injected || res.InjectReason != InjectServerState {
		t.Errorf("continuation of stored response must not be injected (reason %q)", res.InjectReason)
	}
}

// TestInjectReason pins the vocabulary the log line relies on: every request
// says why the notice was added or skipped.
func TestInjectReason(t *testing.T) {
	for _, tc := range []struct {
		name   string
		rw     *Rewriter
		path   string
		body   string
		reason string
	}{
		{"added", newRW(true), "/v1/chat/completions", `{"messages":[]}`, InjectAdded},
		{"already present", newRW(true), "/v1/chat/completions",
			`{"messages":[{"role":"system","content":"` + InstructionMarker + `"}]}`, InjectPresent},
		{"stored response", newRW(true), "/v1/responses",
			`{"previous_response_id":"resp_1"}`, InjectServerState},
		{"disabled", newRW(false), "/v1/chat/completions", `{"messages":[]}`, InjectDisabled},
		{"no target", newRW(true), "/v1/images/generations", `{"prompt":"a cat"}`, InjectNoTarget},
		{"not needed", &Rewriter{Detector: det, Inject: true, Sent: vault.NewSent(0), Upstream: "test"},
			"/v1/chat/completions", `{"messages":[]}`, InjectNotNeeded},
	} {
		res, err := tc.rw.JSON(context.Background(), adapter(t, tc.path), []byte(tc.body), caller())
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if res.InjectReason != tc.reason {
			t.Errorf("%s: reason %q, want %q", tc.name, res.InjectReason, tc.reason)
		}
	}
}

// TestCountsRecordsScanShape keeps the diagnostic counters honest: a text
// answered from the sent memo is counted as frozen, not as scanned.
func TestCountsRecordsScanShape(t *testing.T) {
	rw := newRW(true)
	a := adapter(t, "/v1/chat/completions")
	body := []byte(`{"messages":[{"role":"user","content":"the first message"},{"role":"user","content":"the second message"}]}`)
	res, err := rw.JSON(context.Background(), a, body, caller())
	if err != nil {
		t.Fatal(err)
	}
	if res.Units != 2 || res.Frozen != 0 {
		t.Errorf("first pass: units %d frozen %d", res.Units, res.Frozen)
	}
	res, err = rw.JSON(context.Background(), a, body, caller())
	if err != nil {
		t.Fatal(err)
	}
	if res.Units != 2 || res.Frozen != 2 {
		t.Errorf("second pass: units %d frozen %d", res.Units, res.Frozen)
	}
}

func TestPromptOnlyFields(t *testing.T) {
	a := adapter(t, "/v1/images/generations")
	raw := []byte(`{"model":"gpt-image-1","prompt":"a poster saying ` + ghToken + `","user":"` + ghToken + `"}`)
	res, err := newRW(true).JSON(context.Background(), a, raw, caller())
	if err != nil {
		t.Fatal(err)
	}
	out := string(res.Body)
	if strings.Contains(out, "poster saying "+ghToken) || res.Injected {
		t.Fatalf("prompt not scanned or notice injected: %s", out)
	}
	if !strings.Contains(out, `"user":"`+ghToken) {
		t.Fatal("fields outside the list must stay untouched")
	}
}

func TestDataURISkipped(t *testing.T) {
	a := adapter(t, "/v1/chat/completions")
	raw := []byte(`{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,` + strings.Repeat("Zx8Kq2Lm9Pw4Rt7Y", 8) + `"}}]}]}`)
	res, _ := newRW(false).JSON(context.Background(), a, raw, caller())
	if res.Count() != 0 {
		t.Fatalf("image data URI scanned: %v", res.Replaced)
	}
}

func TestTooDeep(t *testing.T) {
	a := adapter(t, "/v1/chat/completions")
	raw := []byte(strings.Repeat("[", 2000) + strings.Repeat("]", 2000))
	if _, err := newRW(false).JSON(context.Background(), a, raw, caller()); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("err = %v", err)
	}
	if _, err := newRW(false).JSON(context.Background(), a, []byte(`{"a":`), caller()); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("err = %v", err)
	}
}

func TestEscapedSecretInJSON(t *testing.T) {
	a := adapter(t, "/v1/chat/completions")
	// The token is written with \u escapes in the raw body.
	esc := strings.ReplaceAll(ghToken, "_", `\u005f`)
	raw := []byte(`{"messages":[{"role":"user","content":"tok ` + esc + ` end"}]}`)
	c := caller()
	res, err := newRW(false).JSON(context.Background(), a, raw, c)
	if err != nil {
		t.Fatal(err)
	}
	want := `"tok ` + c.Placeholder(ghToken) + ` end"`
	if !strings.Contains(string(res.Body), want) {
		t.Fatalf("got %s", res.Body)
	}
}

func TestMultipart(t *testing.T) {
	a := adapter(t, "/v1/audio/transcriptions")
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	w.WriteField("model", "whisper-1")
	w.WriteField("prompt", "names: "+ghToken)
	fw, _ := w.CreateFormFile("file", "a.wav")
	fw.Write([]byte("RIFF....binary " + ghToken))
	w.Close()
	res, err := newRW(false).Multipart(context.Background(), a, buf.Bytes(), w.FormDataContentType(), caller())
	if err != nil {
		t.Fatal(err)
	}
	r := multipart.NewReader(bytes.NewReader(res.Body), w.Boundary())
	form, err := r.ReadForm(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(form.Value["prompt"][0], ghToken) || form.Value["model"][0] != "whisper-1" {
		t.Fatalf("prompt not rewritten: %v", form.Value)
	}
	f, _ := form.File["file"][0].Open()
	data := make([]byte, 100)
	n, _ := f.Read(data)
	if !strings.Contains(string(data[:n]), ghToken) {
		t.Fatal("file part must be forwarded unchanged")
	}
}

func BenchmarkChat64KB(b *testing.B) {
	a := adapter(b, "/v1/chat/completions")
	var msgs []any
	for i := 0; i < 64; i++ {
		msgs = append(msgs, map[string]string{"role": "user", "content": strings.Repeat("Lorem ipsum dolor sit amet, consectetur adipiscing elit. ", 18)})
	}
	raw, _ := json.Marshal(map[string]any{"model": "m", "messages": msgs})
	rw := newRW(true)
	c := caller()
	b.SetBytes(int64(len(raw)))
	for b.Loop() {
		if _, err := rw.JSON(context.Background(), a, raw, c); err != nil {
			b.Fatal(err)
		}
	}
}

// A value sent as written in turn 1 (no context) is recognised in turn 2 (a
// new message gives it one). The known-value rescan must not rewrite turn
// 1's history: the upstream already saw that plaintext, so masking it there
// gains nothing and rebuilds the whole prompt cache (design 7.8).
func TestLateKnownValueDoesNotRewriteHistory(t *testing.T) {
	a := adapter(t, "/v1/chat/completions")
	c := caller()
	rw := newRW(true)
	weak := "Sup3rS3cretPw9x"

	body := func(msgs []map[string]string) []byte {
		b, _ := json.Marshal(struct {
			Model    string              `json:"model"`
			Messages []map[string]string `json:"messages"`
		}{"m", msgs})
		return b
	}
	hist := []map[string]string{{"role": "user", "content": "the value is " + weak + " remember it"}}

	var prev []byte
	for turn := 1; turn <= 4; turn++ {
		msgs := append([]map[string]string{}, hist...)
		if turn >= 2 {
			msgs = append(msgs, map[string]string{"role": "user", "content": "the password is " + weak})
		}
		if turn >= 3 {
			msgs = append(msgs, map[string]string{"role": "assistant", "content": "noted"},
				map[string]string{"role": "user", "content": "thanks"})
		}
		res, err := rw.JSON(context.Background(), a, body(msgs), c)
		if err != nil {
			t.Fatal(err)
		}
		// The notice itself contains "<SECRET_TYPE_xxxxxxxx>", which is not
		// a placeholder; match the real syntax.
		masked := phRe.Match(res.Body)
		if turn == 1 && masked {
			t.Fatalf("turn 1 should have no context to match: %s", res.Body)
		}
		if turn >= 2 && !masked {
			t.Fatalf("turn %d should mask the new message: %s", turn, res.Body)
		}
		if prev != nil {
			head := prev[:len(prev)-2] // strip the closing "]}" of messages/model
			if !bytes.HasPrefix(res.Body, head) {
				t.Fatalf("turn %d rewrote history:\nprev %s\ncur  %s", turn, prev, res.Body)
			}
		}
		prev = res.Body
	}
}

func TestSentMemoBounds(t *testing.T) {
	s := vault.NewSent(2)
	long := strings.Repeat("x", 100)
	for i := 0; i < 5; i++ {
		s.Put("c", "u", "", long+string(rune('a'+i)), []vault.Span{{Start: 0, End: 1, Rule: "r"}})
	}
	if s.Len() != 2 {
		t.Fatalf("Len = %d, want 2", s.Len())
	}
	if _, ok := s.Get("c", "u", "", long+"a"); ok {
		t.Fatal("evicted entry still present")
	}
	if _, ok := s.Get("c", "u", "", long+"e"); !ok {
		t.Fatal("newest entry missing")
	}
	// Texts shorter than the detector's minimum are not remembered.
	s.Put("c", "u", "", "tiny", []vault.Span{{Start: 0, End: 1}})
	if _, ok := s.Get("c", "u", "", "tiny"); ok {
		t.Fatal("tiny text remembered")
	}
	// A different upstream is a different key.
	s.Put("c", "u1", "", long+"z", []vault.Span{{Start: 0, End: 1}})
	if _, ok := s.Get("c", "u2", "", long+"z"); ok {
		t.Fatal("upstream not part of the key")
	}
}

// Reserved keys the upstream validates must never be masked (design 4.2).
func TestReservedKeys(t *testing.T) {
	a := adapter(t, "/v1/responses")
	raw := []byte(`{"model":"m","input":[{"type":"function_call","namespace":"ghp_NqVwYS81VP7Hb1DX8pQ2mZ7xL4kR9tWcB3vE",` +
		`"server_label":"ghp_NqVwYS81VP7Hb1DX8pQ2mZ7xL4kR9tWcB3vE",` +
		`"reasoning_effort":"ghp_NqVwYS81VP7Hb1DX8pQ2mZ7xL4kR9tWcB3vE",` +
		`"stop_reason":"ghp_NqVwYS81VP7Hb1DX8pQ2mZ7xL4kR9tWcB3vE",` +
		`"approval_request_id":"ghp_NqVwYS81VP7Hb1DX8pQ2mZ7xL4kR9tWcB3vE",` +
		`"output_ids":["ghp_NqVwYS81VP7Hb1DX8pQ2mZ7xL4kR9tWcB3vE"]}]}`)
	res, err := newRW(false).JSON(context.Background(), a, raw, caller())
	if err != nil {
		t.Fatal(err)
	}
	if res.Count() != 0 {
		t.Fatalf("reserved keys masked: %v\n%s", res.Replaced, res.Body)
	}
}

// A rule that matches on context also matches code, paths, versions and
// moments; those must go as written (design 4.3.1).
func TestVetoedValuesGoAsWritten(t *testing.T) {
	a := adapter(t, "/v1/chat/completions")
	cases := []string{
		"PRIVATE_KEY_PATH=~/.ssh/id_ed25519",
		"access_token = get_access_token_v2",
		"secret: env.SECRET_V2",
		`jsonwebtoken = "9.2.0-beta1"`,
		`tokenizer = "2.4.0-beta02"`,
		"UI_PASSWORD= UI_ADDR=127.0.0.1:39117 ./svc",
		`"access_token_expires_at": "2026-08-30T11:44:31Z"`,
		"internal/auth/token.go:L643-669",
	}
	for _, s := range cases {
		raw, _ := json.Marshal(map[string]any{"model": "m", "messages": []any{
			map[string]string{"role": "user", "content": s},
		}})
		res, err := newRW(false).JSON(context.Background(), a, raw, caller())
		if err != nil {
			t.Fatal(err)
		}
		if res.Count() != 0 {
			t.Errorf("%q masked as %v", s, res.Replaced)
		}
	}
}

// xAI TTS and Codex search carry user text in their own fields; those must
// be scanned (a plain text field is not a conversation history, so no
// notice is injected).
func TestPromptOnlyExtraAdapters(t *testing.T) {
	cases := []struct{ path, body, want string }{
		{"/v1/tts",
			`{"text":"read this: ghp_NqVwYS81VP7Hb1DX8pQ2mZ7xL4kR9tWcB3vE","voice_id":"v1","language":"auto"}`,
			`"text":"read this: <SECRET_GITHUB_TOKEN_`},
		{"/v1/alpha/search",
			`{"id":"s1","model":"gpt-5","commands":{"search_query":[{"q":"ghp_NqVwYS81VP7Hb1DX8pQ2mZ7xL4kR9tWcB3vE"}]}}`,
			`<SECRET_GITHUB_TOKEN_`},
	}
	for _, c := range cases {
		a := adapter(t, c.path)
		res, err := newRW(true).JSON(context.Background(), a, []byte(c.body), caller())
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(res.Body), c.want) || res.Injected {
			t.Errorf("%s: %s", c.path, res.Body)
		}
	}
	// The frozen search fields must not be rewritten.
	a := adapter(t, "/v1/alpha/search")
	res, _ := newRW(false).JSON(context.Background(), a, []byte(`{"id":"ghp_NqVwYS81VP7Hb1DX8pQ2mZ7xL4kR9tWcB3vE","model":"m","commands":{"search_query":[{"q":"x"}]}}`), caller())
	if strings.Contains(string(res.Body), "<SECRET_") {
		t.Fatalf("frozen id rewritten: %s", res.Body)
	}
}

// An agent re-sends its whole history every turn. That history has already
// been sent, so its spans are frozen and detection must not run on it again:
// only the new messages cost anything.
func TestRepeatedHistoryIsCheap(t *testing.T) {
	setup(t)
	a := adapter(t, "/v1/chat/completions")
	c := caller()
	rw := newRW(true)
	ctx := context.Background()

	// Take a conversation and grow it one message per turn, the way an agent
	// does. Every earlier message has already been sent.
	var req struct {
		Model    string            `json:"model"`
		Messages []json.RawMessage `json:"messages"`
	}
	json.Unmarshal(chatBody(16000, 50), &req)

	turn := func() float64 {
		body, err := json.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		res, err := rw.JSON(ctx, a, body, c)
		if err != nil {
			t.Fatal(err)
		}
		if res.Count() == 0 {
			t.Fatal("expected replacements")
		}
		return float64(time.Since(start).Microseconds()) / 1000
	}

	first := turn()
	var later []float64
	for i := 0; i < 3; i++ {
		req.Messages = append(req.Messages,
			json.RawMessage(`{"role":"user","content":"a new turn with no secrets in it"}`))
		later = append(later, turn())
	}
	// The first turn pays for detection over the whole history; later turns
	// only pay for the new message, because the rest is frozen in the memo.
	t.Logf("first %.1f ms, later %v", first, later)
	for _, l := range later {
		if l > first/2 {
			t.Errorf("a repeated history cost %.1f ms against %.1f ms on the first turn; "+
				"detection should be skipped for frozen text", l, first)
		}
	}
}
