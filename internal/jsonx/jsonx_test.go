package jsonx

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestParseMatchesStdlib(t *testing.T) {
	inputs := []string{
		`{"a":"b","c":[1,2.5e-3,true,false,null,{"d":"\u00e9\ud83d\ude00\n\"x\\"}]}`,
		"\xEF\xBB\xBF {\"k\" : \"v\" } ",
		`"plain"`,
		`[]`,
		`{}`,
		`{"s":"\u0041\/\b\f\r\t"}`,
	}
	for _, in := range inputs {
		doc, err := Parse([]byte(in), 0)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		var want []string
		var std any
		if err := json.Unmarshal([]byte(strings.TrimPrefix(in, "\xEF\xBB\xBF")), &std); err != nil {
			t.Fatal(err)
		}
		collect(std, &want)
		var got []string
		Walk(doc.Root, func(_ []string, n *Node, _ []*Node) { got = append(got, n.Str) })
		slices.Sort(got)
		slices.Sort(want)
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

// collect gathers string leaves; callers sort them because map iteration
// order is random.
func collect(v any, out *[]string) {
	switch x := v.(type) {
	case string:
		*out = append(*out, x)
	case []any:
		for _, e := range x {
			collect(e, out)
		}
	case map[string]any:
		for _, e := range x {
			collect(e, out)
		}
	}
}

func TestParseErrors(t *testing.T) {
	bad := []string{``, `{`, `{"a"}`, `[1,]`, `"\x"`, "\"a\x01\"", `01x`, `{"a":1}x`, `"\u12"`, `tru`}
	for _, in := range bad {
		if _, err := Parse([]byte(in), 0); err == nil {
			t.Errorf("%q: expected error", in)
		}
	}
}

func TestDepthLimit(t *testing.T) {
	in := strings.Repeat("[", 10) + strings.Repeat("]", 10)
	if _, err := Parse([]byte(in), 9); err != ErrTooDeep {
		t.Fatalf("want ErrTooDeep, got %v", err)
	}
	if _, err := Parse([]byte(in), 10); err != nil {
		t.Fatal(err)
	}
}

func TestDuplicateKeys(t *testing.T) {
	doc, err := Parse([]byte(`{"a":1,"b":{"x":1},"a":"two"}`), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !doc.DuplicateKeys {
		t.Fatal("duplicate not flagged")
	}
	if doc.Root.GetString("a") != "two" {
		t.Fatal("Get should return last duplicate")
	}
}

func TestRawRangeAndApply(t *testing.T) {
	raw := []byte(`{"x":"key=\u0073k-abc\n tail", "y": 1}`)
	doc, err := Parse(raw, 0)
	if err != nil {
		t.Fatal(err)
	}
	n := doc.Root.Get("x")
	from := strings.Index(n.Str, "sk-abc")
	s, e := doc.RawRange(n, from, from+len("sk-abc"))
	if got := string(raw[s:e]); got != `\u0073k-abc` {
		t.Fatalf("raw range = %q", got)
	}
	out, err := Apply(raw, []Edit{{Start: s, End: e, Text: AppendEscaped(nil, "<P>")}})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"x":"key=<P>\n tail", "y": 1}`; string(out) != want {
		t.Fatalf("got %s", out)
	}
	if !json.Valid(out) {
		t.Fatal("invalid json after edit")
	}
}

func TestApplyNoEditsReturnsSameSlice(t *testing.T) {
	raw := []byte(`{"a":"b"}`)
	out, _ := Apply(raw, nil)
	if &out[0] != &raw[0] {
		t.Fatal("expected identical slice")
	}
	if _, err := Apply(raw, []Edit{{1, 4, nil}, {3, 5, nil}}); err == nil {
		t.Fatal("expected overlap error")
	}
}

func TestAppendEscapedRoundTrip(t *testing.T) {
	for _, s := range []string{"plain", "q\"b\\s", "nl\n\r\t\x01", "é😀<>&"} {
		enc := `"` + string(AppendEscaped(nil, s)) + `"`
		var got string
		if err := json.Unmarshal([]byte(enc), &got); err != nil || got != s {
			t.Errorf("%q -> %s -> %q (%v)", s, enc, got, err)
		}
	}
}
