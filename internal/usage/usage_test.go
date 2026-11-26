package usage

import (
	"io"
	"strings"
	"testing"
)

func TestFromJSON(t *testing.T) {
	for _, c := range []struct {
		name string
		body string
		want Info
	}{
		{
			name: "openai chat",
			body: `{"model":"gpt-4o","usage":{"prompt_tokens":1200,"completion_tokens":34,` +
				`"prompt_tokens_details":{"cached_tokens":1024}}}`,
			want: Info{Model: "gpt-4o", InputTokens: 1200, CachedTokens: 1024, OutputTokens: 34},
		},
		{
			name: "openai responses",
			body: `{"model":"gpt-5","usage":{"input_tokens":900,"output_tokens":12,` +
				`"input_tokens_details":{"cached_tokens":768}}}`,
			want: Info{Model: "gpt-5", InputTokens: 900, CachedTokens: 768, OutputTokens: 12},
		},
		{
			name: "anthropic",
			body: `{"model":"claude-sonnet-4-5","usage":{"input_tokens":18,"output_tokens":220,` +
				`"cache_read_input_tokens":48000,"cache_creation_input_tokens":1024}}`,
			want: Info{Model: "claude-sonnet-4-5", InputTokens: 18, CachedTokens: 48000, OutputTokens: 220},
		},
		{
			name: "gemini",
			body: `{"usageMetadata":{"promptTokenCount":5000,"candidatesTokenCount":88,` +
				`"cachedContentTokenCount":4096}}`,
			want: Info{InputTokens: 5000, CachedTokens: 4096, OutputTokens: 88},
		},
		{
			name: "no usage",
			body: `{"id":"chatcmpl-1","choices":[]}`,
			want: Info{},
		},
		{
			name: "truncated",
			body: `{"usage":{"prompt_tokens":12`,
			want: Info{},
		},
	} {
		if got := FromJSON([]byte(c.body)); got != c.want {
			t.Errorf("%s: got %+v want %+v", c.name, got, c.want)
		}
	}
}

func TestHitRate(t *testing.T) {
	i := Info{InputTokens: 1000, CachedTokens: 900}
	if r := i.HitRate(); r < 0.899 || r > 0.901 {
		t.Errorf("hit rate %v", r)
	}
	if r := (Info{}).HitRate(); r != 0 {
		t.Errorf("empty hit rate %v", r)
	}
}

// readAll drives the watcher the way the proxy does: through Read until EOF.
func readAll(t *testing.T, body string, chunk int) Info {
	t.Helper()
	var got Info
	r := Watch(io.NopCloser(strings.NewReader(body)), func(i Info) { got = i })
	buf := make([]byte, chunk)
	for {
		_, err := r.Read(buf)
		if err != nil {
			break
		}
	}
	r.Close()
	return got
}

func TestWatchSSE(t *testing.T) {
	stream := strings.Join([]string{
		`data: {"id":"1","choices":[{"delta":{"content":"hi"}}],"usage":null}`,
		``,
		`data: {"id":"1","model":"gpt-4o","choices":[],"usage":{"prompt_tokens":2000,` +
			`"completion_tokens":51,"prompt_tokens_details":{"cached_tokens":1920}}}`,
		``,
		`data: [DONE]`,
		``,
	}, "\n")
	want := Info{Model: "gpt-4o", InputTokens: 2000, CachedTokens: 1920, OutputTokens: 51}
	// One byte at a time is the worst case for line buffering.
	for _, chunk := range []int{1, 3, 7, 4096} {
		if got := readAll(t, stream, chunk); got != want {
			t.Errorf("chunk %d: got %+v want %+v", chunk, got, want)
		}
	}
}

func TestWatchPlainJSON(t *testing.T) {
	body := `{"model":"gpt-4o","usage":{"prompt_tokens":42,"completion_tokens":7}}`
	want := Info{Model: "gpt-4o", InputTokens: 42, OutputTokens: 7}
	for _, chunk := range []int{1, 5, 4096} {
		if got := readAll(t, body, chunk); got != want {
			t.Errorf("chunk %d: got %+v want %+v", chunk, got, want)
		}
	}
}

// A body without the key is never decoded, so an enormous non-JSON body
// costs nothing.
func TestWatchIgnoresOtherBodies(t *testing.T) {
	got := readAll(t, strings.Repeat("x", 300000), 4096)
	if !got.Empty() {
		t.Errorf("got %+v", got)
	}
}

func TestWatchReportsOnce(t *testing.T) {
	n := 0
	r := Watch(io.NopCloser(strings.NewReader(`{"usage":{"prompt_tokens":1}}`)), func(Info) { n++ })
	io.Copy(io.Discard, r)
	r.Close()
	r.Close()
	if n != 1 {
		t.Errorf("reported %d times", n)
	}
}
