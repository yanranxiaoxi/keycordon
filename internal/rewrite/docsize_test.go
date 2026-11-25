package rewrite

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// TestDocumentSize answers "how big is a request for N tokens", which is what
// limits.max_body_bytes has to accommodate.
//
// The answer depends on the content, not on the model: cl100k splits text into
// tokens of a few bytes each, and how many bytes a token covers is a property
// of the script.
//
//	JSON / code   ~4.8 bytes/token  short tokens, lots of punctuation
//	English       ~4.0
//	Python / Go   ~3.5
//	base64        ~3.0              fixed by the encoding (4 chars per 3 bytes)
//	hex           ~2.0              fixed by the encoding
//	Chinese       ~1.5              one CJK character is often one token
//
// The ratios are the ones the scale test in scale_test.go relies on for
// English (4 bytes/token) and the encoding-imposed ones for base64 and hex.
// Images are the exception: a model bills them by tile, so a megabyte of PNG
// can cost a few thousand tokens.
func TestDocumentSize(t *testing.T) {
	body := func(msgs []any) []byte {
		b, err := json.Marshal(map[string]any{"model": "m", "messages": msgs})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	text := func(s string) []byte {
		return body([]any{map[string]string{"role": "user", "content": s}})
	}

	// fill grows unit until it holds at least n bytes.
	fill := func(unit string, n int) string {
		return strings.Repeat(unit, n/len(unit)+1)[:n]
	}

	const tokens = 2_000_000 // Grok's context, the largest in use
	cases := []struct {
		name  string
		ratio float64
		body  []byte
	}{
		{"english", 4.0, text(fill("The deployment runs under systemd and writes logs. ", int(tokens*4.0)))},
		{"json", 4.8, text(fill(`{"id":12345,"status":"running","cpu":0.42},`, int(tokens*4.8)))},
		{"code", 3.5, text(fill("\tif err := s.run(ctx); err != nil {\n\t\treturn err\n\t}\n", int(tokens*3.5)))},
		{"chinese", 1.5, text(fill("这是一段普通的中文说明文字。", int(tokens*1.5)))},
		{"hex", 2.0, text(fill("0123456789abcdef", int(tokens*2.0)))},
		{"base64", 3.0, text(fill("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=", int(tokens*3.0)))},
	}
	for _, c := range cases {
		t.Logf("%-8s %6.1f bytes/token -> %6.1f MiB", c.name, c.ratio, float64(len(c.body))/(1<<20))
	}

	// The worst realistic request: many images. A 4 MiB PNG is 5.6 MiB of
	// base64 and costs a few thousand tokens per tile, so the bytes per token
	// is hundreds of times the text ratio.
	img := base64.StdEncoding.EncodeToString(make([]byte, 4<<20))
	for _, n := range []int{1, 10, 50} {
		parts := []any{map[string]string{"type": "text", "text": "describe these"}}
		for i := 0; i < n; i++ {
			parts = append(parts, map[string]any{
				"type":      "image_url",
				"image_url": map[string]string{"url": "data:image/png;base64," + img},
			})
		}
		t.Logf("%3d x 4 MiB images -> %7.1f MiB body", n, float64(len(body([]any{
			map[string]any{"role": "user", "content": parts},
		})))/(1<<20))
	}
}
