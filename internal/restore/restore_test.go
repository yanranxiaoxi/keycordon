package restore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"gitlab.soraharu.com/XiaoXi/keycordon/internal/protocol"
	"gitlab.soraharu.com/XiaoXi/keycordon/internal/vault"
)

var reg *protocol.Registry

func adapter(t *testing.T, path string) *protocol.Adapter {
	t.Helper()
	if reg == nil {
		r, err := protocol.Load(protocol.Options{})
		if err != nil {
			t.Fatal(err)
		}
		reg = r
	}
	a := reg.Match("POST", path, false)
	if a == nil {
		t.Fatal("no adapter")
	}
	return a
}

const secret = `pa"ss\word-Zx8Kq2Lm9Pw4`

func newCaller() (*vault.Caller, string) {
	c := vault.New([]byte("0123456789abcdef0123456789abcdef"), vault.Options{}).Caller("local")
	return c, c.Placeholder(secret)
}

func jsonStr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestJSONRestore(t *testing.T) {
	c, ph := newCaller()
	a := adapter(t, "/v1/chat/completions")
	args := `{"cmd":"login ` + ph + `"}`
	body := `{"choices":[{"message":{"content":"use ` + ph + ` now","reasoning_content":"` + ph + `","tool_calls":[{"function":{"arguments":` + jsonStr(args) + `}}]}}]}`
	out := JSON(a, c, []byte(body))
	var resp struct {
		Choices []struct {
			Message struct {
				Content          string
				ReasoningContent string `json:"reasoning_content"`
				ToolCalls        []struct {
					Function struct{ Arguments string }
				} `json:"tool_calls"`
			}
		}
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	m := resp.Choices[0].Message
	if m.Content != "use "+secret+" now" {
		t.Fatalf("content %q", m.Content)
	}
	if m.ReasoningContent != ph {
		t.Fatal("reasoning must not be restored")
	}
	var inner map[string]string
	if err := json.Unmarshal([]byte(m.ToolCalls[0].Function.Arguments), &inner); err != nil || inner["cmd"] != "login "+secret {
		t.Fatalf("arguments %q err %v", m.ToolCalls[0].Function.Arguments, err)
	}
	// Escaped '<' in the raw JSON is handled because restore works on decoded strings.
	esc := strings.ReplaceAll(body, "<", `\u003c`)
	if !bytes.Contains(JSON(a, c, []byte(esc)), []byte("use pa\\\"ss")) {
		t.Fatal("escaped placeholder not restored")
	}
	// No marker: identical slice.
	plain := []byte(`{"a":"b"}`)
	if &JSON(a, c, plain)[0] != &plain[0] {
		t.Fatal("body without marker must be returned as is")
	}
}

func TestOtherCallerAndUnknown(t *testing.T) {
	_, ph := newCaller()
	other := vault.New([]byte("0123456789abcdef0123456789abcdef"), vault.Options{}).Caller("other")
	a := adapter(t, "/v1/chat/completions")
	body := []byte(`{"x":"` + ph + ` <SECRET_TOKEN_00000000>"}`)
	if !bytes.Equal(JSON(a, other, body), body) {
		t.Fatal("another caller must not restore")
	}
}

// feed writes data in chunks of size n and returns the output.
func feed(t *testing.T, s Stream, buf *bytes.Buffer, data string, n int) string {
	t.Helper()
	for i := 0; i < len(data); i += n {
		if _, err := s.Write([]byte(data[i:min(i+n, len(data))])); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func chatChunk(field, text string) string {
	var delta string
	switch field {
	case "content":
		delta = `{"content":` + jsonStr(text) + `}`
	case "args":
		delta = `{"tool_calls":[{"index":0,"function":{"arguments":` + jsonStr(text) + `}}]}`
	case "reasoning":
		delta = `{"reasoning_content":` + jsonStr(text) + `}`
	}
	return `data: {"choices":[{"index":0,"delta":` + delta + `}]}` + "\n\n"
}

// collectChat concatenates the deltas of a chat SSE stream.
func collectChat(t *testing.T, out string) (content, args, reasoning string) {
	t.Helper()
	for _, ev := range strings.Split(out, "\n\n") {
		d, ok := strings.CutPrefix(ev, "data: ")
		if !ok || d == "[DONE]" {
			continue
		}
		var chunk struct {
			Choices []struct {
				Delta struct {
					Content   string
					Reasoning string `json:"reasoning_content"`
					ToolCalls []struct {
						Function struct{ Arguments string }
					} `json:"tool_calls"`
				}
			}
		}
		if err := json.Unmarshal([]byte(d), &chunk); err != nil {
			t.Fatalf("bad event %q: %v", d, err)
		}
		dl := chunk.Choices[0].Delta
		content += dl.Content
		reasoning += dl.Reasoning
		for _, tc := range dl.ToolCalls {
			args += tc.Function.Arguments
		}
	}
	return
}

func TestSSEChatSplitEverywhere(t *testing.T) {
	c, ph := newCaller()
	a := adapter(t, "/v1/chat/completions")
	text := "key=" + ph + " end <b> and <SECRET_TOKEN_0000"
	args := `{"p":"` + ph + `"}`
	for cut := 0; cut <= len(text); cut++ {
		for _, chunkSize := range []int{1, 7, 4096} {
			stream := chatChunk("reasoning", "think "+ph) +
				chatChunk("content", text[:cut]) +
				chatChunk("content", text[cut:]) +
				chatChunk("args", args[:min(cut, len(args))]) +
				chatChunk("args", args[min(cut, len(args)):]) +
				"data: [DONE]\n\n"
			var buf bytes.Buffer
			out := feed(t, NewSSE(a, c, &buf, nil), &buf, stream, chunkSize)
			content, gotArgs, reasoning := collectChat(t, out)
			want := strings.Replace(text, ph, secret, 1)
			if content != want {
				t.Fatalf("cut %d size %d: content %q want %q", cut, chunkSize, content, want)
			}
			var inner map[string]string
			if err := json.Unmarshal([]byte(gotArgs), &inner); err != nil || inner["p"] != secret {
				t.Fatalf("cut %d: args %q (%v)", cut, gotArgs, err)
			}
			if reasoning != "think "+ph {
				t.Fatal("reasoning restored")
			}
			if strings.Count(out, "data: ") != 6 || !strings.HasSuffix(out, "data: [DONE]\n\n") {
				t.Fatalf("event sequence changed:\n%s", out)
			}
		}
	}
}

func TestSSEPassthroughUnchanged(t *testing.T) {
	c, _ := newCaller()
	a := adapter(t, "/v1/messages")
	stream := "event: message_start\r\ndata: {\"type\":\"message_start\"}\r\n\r\n: ping\r\n\r\nevent: content_block_delta\r\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"a < b\"}}\r\n\r\n"
	var buf bytes.Buffer
	if out := feed(t, NewSSE(a, c, &buf, nil), &buf, stream, 3); out != stream {
		t.Fatalf("stream changed:\n%q\n%q", out, stream)
	}
}

func TestSSEAnthropic(t *testing.T) {
	c, ph := newCaller()
	a := adapter(t, "/v1/messages")
	ev := func(typ, body string) string {
		return "event: " + typ + "\ndata: " + body + "\n\n"
	}
	half := len(ph) / 2
	stream := ev("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"`+ph+`"}}`) +
		ev("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"`+ph+`"}}`) +
		ev("content_block_delta", `{"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"x`+ph[:half]+`"}}`) +
		ev("content_block_delta", `{"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\"k\":\"`+ph[:3]+`"}}`) +
		ev("content_block_delta", `{"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"`+ph[half:]+`y"}}`) +
		ev("content_block_delta", `{"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"`+ph[3:]+`\"}"}}`) +
		ev("content_block_stop", `{"type":"content_block_stop","index":1}`)
	var buf bytes.Buffer
	out := feed(t, NewSSE(a, c, &buf, nil), &buf, stream, 5)
	var text, js, thinking, sig string
	for _, e := range strings.Split(strings.TrimSpace(out), "\n\n") {
		_, d, _ := strings.Cut(e, "data: ")
		var v struct {
			Delta struct{ Type, Text, PartialJSON, Thinking, Signature string } `json:"delta"`
		}
		json.Unmarshal([]byte(d), &v)
		var raw map[string]map[string]string
		json.Unmarshal([]byte(d), &raw)
		text += v.Delta.Text
		js += raw["delta"]["partial_json"]
		thinking += v.Delta.Thinking
		sig += v.Delta.Signature
	}
	if text != "x"+secret+"y" {
		t.Fatalf("text %q\n%s", text, out)
	}
	var inner map[string]string
	if err := json.Unmarshal([]byte(js), &inner); err != nil || inner["k"] != secret {
		t.Fatalf("partial_json %q", js)
	}
	if thinking != ph || sig != ph {
		t.Fatal("thinking/signature must not be restored")
	}
}

func TestSSEResponses(t *testing.T) {
	c, ph := newCaller()
	a := adapter(t, "/v1/responses")
	ev := func(typ, extra string) string {
		return "event: " + typ + "\ndata: {\"type\":\"" + typ + "\"," + extra + "}\n\n"
	}
	stream := ev("response.output_text.delta", `"item_id":"msg_1","output_index":0,"content_index":0,"delta":"a`+ph[:10]+`"`) +
		ev("response.output_text.delta", `"item_id":"msg_1","output_index":0,"content_index":0,"delta":"`+ph[10:]+`b"`) +
		ev("response.output_text.done", `"item_id":"msg_1","text":"a`+ph+`b"`) +
		ev("response.completed", `"response":{"output":[{"type":"reasoning","summary":[{"text":"`+ph+`"}]},{"type":"message","content":[{"type":"output_text","text":"a`+ph+`b"}]}]}`)
	var buf bytes.Buffer
	out := feed(t, NewSSE(a, c, &buf, nil), &buf, stream, 11)
	if strings.Count(out, ph) != 1 || !strings.Contains(out, `"summary":[{"text":"`+ph) {
		t.Fatalf("only the reasoning summary keeps the placeholder:\n%s", out)
	}
	if strings.Count(out, `a`+jsonStr(secret)[1:len(jsonStr(secret))-1]+`b`) != 2 {
		t.Fatalf("done/completed not restored:\n%s", out)
	}
}

func TestGeminiJSONArray(t *testing.T) {
	c, ph := newCaller()
	a := adapter(t, "/v1beta/models/g:streamGenerateContent")
	el := func(text string, thought bool) string {
		th := ""
		if thought {
			th = `"thought":true,`
		}
		return `{"candidates":[{"index":0,"content":{"role":"model","parts":[{` + th + `"text":` + jsonStr(text) + `}]}}]}`
	}
	stream := "[" + el("t "+ph, true) + ",\r\n" + el("x"+ph[:5], false) + ",\r\n" + el(ph[5:]+"y", false) + "]"
	for _, n := range []int{1, 3, 1000} {
		var buf bytes.Buffer
		out := feed(t, NewJSONArray(a, c, &buf, nil), &buf, stream, n)
		var arr []struct {
			Candidates []struct {
				Content struct {
					Parts []struct {
						Text    string
						Thought bool
					}
				}
			}
		}
		if err := json.Unmarshal([]byte(out), &arr); err != nil {
			t.Fatalf("n=%d invalid output %v:\n%s", n, err, out)
		}
		var text string
		for _, e := range arr[1:] {
			text += e.Candidates[0].Content.Parts[0].Text
		}
		if text != "x"+secret+"y" || arr[0].Candidates[0].Content.Parts[0].Text != "t "+ph {
			t.Fatalf("n=%d text %q", n, text)
		}
	}
}

func TestNDJSON(t *testing.T) {
	c, ph := newCaller()
	a := adapter(t, "/api/chat")
	stream := fmt.Sprintf("{\"message\":{\"content\":%s}}\n{\"message\":{\"content\":%s},\"done\":true}\n", jsonStr("a"+ph[:4]), jsonStr(ph[4:]+"b"))
	var buf bytes.Buffer
	out := feed(t, NewNDJSON(a, c, &buf, nil), &buf, stream, 2)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	var got string
	for _, l := range lines {
		var v struct{ Message struct{ Content string } }
		if err := json.Unmarshal([]byte(l), &v); err != nil {
			t.Fatalf("%v: %q", err, l)
		}
		got += v.Message.Content
	}
	if got != "a"+secret+"b" || len(lines) != 2 {
		t.Fatalf("got %q\n%s", got, out)
	}
}

func TestHeldEventFlushedOnClose(t *testing.T) {
	c, _ := newCaller()
	a := adapter(t, "/v1/chat/completions")
	stream := chatChunk("content", "ends with <SECRET_TO")
	var buf bytes.Buffer
	if out := feed(t, NewSSE(a, c, &buf, nil), &buf, stream, 4); out != stream {
		t.Fatalf("held event lost: %q", out)
	}
}
