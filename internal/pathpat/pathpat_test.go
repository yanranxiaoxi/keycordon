package pathpat

import (
	"strings"
	"testing"

	"gitlab.soraharu.com/XiaoXi/keycordon/internal/jsonx"
)

const doc = `{
 "model": "m",
 "messages": [
  {"role": "user", "content": "hello"},
  {"role": "assistant", "content": [
    {"type": "thinking", "thinking": "deep", "signature": "sig"},
    {"type": "text", "text": "answer"}
  ]}
 ],
 "tools": [{"name": "t", "input_schema": {"properties": {"x": {"description": "d"}}}}]
}`

func matched(t *testing.T, pat string) []string {
	t.Helper()
	d, err := jsonx.Parse([]byte(doc), 0)
	if err != nil {
		t.Fatal(err)
	}
	set, err := CompileSet([]string{pat})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	jsonx.Walk(d.Root, func(path []string, n *jsonx.Node, parents []*jsonx.Node) {
		if set.Match(path, parents, n) {
			out = append(out, n.Str)
		}
	})
	return out
}

func TestPatterns(t *testing.T) {
	cases := map[string]string{
		"$.model":                          "m",
		"**.role":                          "user,assistant",
		"messages.[].content":              "hello,deep,sig,thinking,answer,text",
		"**.?type=thinking.thinking":       "deep",
		"**.?type=thinking":                "thinking,deep,sig",
		"**.?type!=thinking.text":          "answer",
		"**.signature":                     "sig",
		"tools.[].input_schema":            "d",
		"messages.*.content.[].?text.type": "text",
		"**":                               "m,user,hello,assistant,thinking,deep,sig,text,answer,t,d",
	}
	for pat, want := range cases {
		got := matched(t, pat)
		if sortJoin(got) != sortJoin(strings.Split(want, ",")) {
			t.Errorf("%s: got %v want %v", pat, got, want)
		}
	}
}

func sortJoin(s []string) string {
	c := append([]string(nil), s...)
	for i := range c {
		for j := i + 1; j < len(c); j++ {
			if c[j] < c[i] {
				c[i], c[j] = c[j], c[i]
			}
		}
	}
	return strings.Join(c, ",")
}

func TestCompileErrors(t *testing.T) {
	for _, s := range []string{"", "$", "a..b", "?"} {
		if _, err := Compile(s); err == nil {
			t.Errorf("%q: expected error", s)
		}
	}
}

func TestGlobSegment(t *testing.T) {
	cases := []struct {
		pat  string
		path []string
		want bool
	}{
		{"**.*_id", []string{"approval_request_id"}, true},
		{"**.*_id", []string{"a", "tool_call_id"}, true},
		{"**.*_id", []string{"id"}, false},
		{"**.*_ids", []string{"output_ids"}, true},
		{"**.*Id", []string{"requestId"}, true},
		{"**.*Ids", []string{"requestIds"}, true},
		{"**.*_id", []string{"[]", "x_id"}, true},
		{"pre*", []string{"prefix"}, true},
		{"pre*", []string{"xprefix"}, false},
		{"*suf", []string{"xsuf"}, true},
	}
	for _, c := range cases {
		p, err := Compile(c.pat)
		if err != nil {
			t.Fatalf("%s: %v", c.pat, err)
		}
		// Build a fake node chain: every segment is an object member.
		parents := make([]*jsonx.Node, len(c.path))
		for i := range parents {
			parents[i] = &jsonx.Node{Kind: jsonx.Object}
		}
		leaf := &jsonx.Node{Kind: jsonx.String, Str: "v"}
		if got := p.Match(c.path, parents, leaf); got != c.want {
			t.Errorf("%s %v = %v, want %v", c.pat, c.path, got, c.want)
		}
	}
	if _, err := Compile("a*b*c"); err == nil {
		t.Fatal("two globs accepted")
	}
}
