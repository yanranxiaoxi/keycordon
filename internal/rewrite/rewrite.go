// Package rewrite replaces secrets in AI request bodies with placeholders.
// It edits only the byte ranges of the affected JSON strings so that every
// other byte of the request stays identical (provider prompt caches).
package rewrite

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"gitlab.soraharu.com/XiaoXi/keycordon/internal/detector"
	"gitlab.soraharu.com/XiaoXi/keycordon/internal/jsonx"
	"gitlab.soraharu.com/XiaoXi/keycordon/internal/protocol"
	"gitlab.soraharu.com/XiaoXi/keycordon/internal/vault"
	"gitlab.soraharu.com/XiaoXi/keycordon/internal/veto"
)

// ErrBadRequest wraps body errors that should be reported as 400.
var ErrBadRequest = errors.New("bad request body")

// Rewriter is safe for concurrent use.
type Rewriter struct {
	Detector *detector.Detector
	// MaxDepth limits JSON nesting, including JSON embedded in strings.
	MaxDepth int
	// Inject adds the placeholder notice. InjectAlways adds it to every
	// filtered request so the prompt prefix never changes when the first
	// placeholder appears (design 7.4).
	Inject       bool
	InjectAlways bool
	// MinLength drops findings shorter than this (matches the detector).
	MinLength int
	// Sent freezes the spans a text was first sent with, so a value that
	// becomes known later never rewrites history (design 7.8).
	Sent *vault.Sent
	// Upstream identifies the upstream in Sent's key: changing it
	// re-decides, since that plaintext never reached the new one.
	Upstream string
}

// Result describes a rewrite.
type Result struct {
	Body []byte
	// Replaced counts replaced occurrences per rule ID ("known" for matches
	// of already known secrets).
	Replaced map[string]int
	Injected bool
}

// Count returns the total number of replacements.
func (r Result) Count() int {
	n := 0
	for _, v := range r.Replaced {
		n += v
	}
	return n
}

// unit is one string scanned on its own.
type unit struct {
	// text is the decoded string; prefix is scanning context ("key": ) that
	// is not part of the string and never replaced.
	text   string
	prefix string
	known  bool
	// chain maps offsets in text to raw body offsets, innermost first.
	chain []link
}

type link struct {
	doc  *jsonx.Doc
	node *jsonx.Node
}

func (u *unit) rawRange(a, b int) (int, int) {
	for _, l := range u.chain {
		a, b = l.doc.RawRange(l.node, a, b)
		// Offsets are now inside the raw text of l.doc, which is the decoded
		// text of the next (outer) link.
	}
	return a, b
}

// JSON rewrites a JSON request body.
func (rw *Rewriter) JSON(ctx context.Context, a *protocol.Adapter, raw []byte, c *vault.Caller) (Result, error) {
	res := Result{Body: raw, Replaced: map[string]int{}}
	maxDepth := rw.MaxDepth
	if maxDepth <= 0 {
		maxDepth = 128
	}
	doc, err := jsonx.Parse(raw, maxDepth)
	if err != nil {
		return res, fmt.Errorf("%w: %v", ErrBadRequest, err)
	}
	units := rw.collect(a, doc, maxDepth)
	edits, err := rw.replace(ctx, units, c, res.Replaced)
	if err != nil {
		return res, err
	}
	if rw.Inject && a.Instruction != nil && (rw.InjectAlways || len(edits) > 0 || c.Len() > 0) &&
		!strings.Contains(string(raw), InstructionMarker) && !continuesStoredResponse(doc.Root) {
		if e, ok := instructionEdit(doc.Root, a.Instruction, Instruction); ok {
			edits = append(edits, e)
			res.Injected = true
		}
	}
	body, err := jsonx.Apply(raw, edits)
	if err != nil {
		return res, err
	}
	res.Body = body
	return res, nil
}

// continuesStoredResponse reports a Responses request that continues a
// server-side conversation; the notice is already part of that history.
func continuesStoredResponse(root *jsonx.Node) bool {
	return root.GetString("previous_response_id") != ""
}

func (rw *Rewriter) collect(a *protocol.Adapter, doc *jsonx.Doc, maxDepth int) []*unit {
	var units []*unit
	trust := !doc.DuplicateKeys
	jsonx.Walk(doc.Root, func(path []string, n *jsonx.Node, parents []*jsonx.Node) {
		if a.Scan == protocol.ScanFields && !a.Fields.Match(path, parents, n) {
			return
		}
		if isBinaryDataURI(n.Str) {
			return
		}
		known := false
		if trust && !a.Payload.Match(path, parents, n) {
			if a.Frozen.Match(path, parents, n) {
				return
			}
			known = a.KnownOnly.Match(path, parents, n)
		}
		units = rw.leafUnits(units, doc, n, contextKey(path, parents), known, nil, maxDepth-len(path))
	})
	return units
}

func contextKey(path []string, parents []*jsonx.Node) string {
	if len(path) == 0 || parents[len(parents)-1].Kind != jsonx.Object {
		return ""
	}
	return path[len(path)-1]
}

// leafUnits adds the units for one string. Strings holding a JSON object or
// array (tool call arguments) are parsed and their strings scanned
// individually, so a secret is registered in its decoded form.
func (rw *Rewriter) leafUnits(units []*unit, doc *jsonx.Doc, n *jsonx.Node, key string, known bool, outer []link, depth int) []*unit {
	chain := append([]link{{doc, n}}, outer...)
	if t := strings.TrimSpace(n.Str); len(t) > 1 && (t[0] == '{' || t[0] == '[') && depth > 1 {
		if inner, err := jsonx.Parse([]byte(n.Str), depth-1); err == nil && (inner.Root.Kind == jsonx.Object || inner.Root.Kind == jsonx.Array) {
			jsonx.Walk(inner.Root, func(path []string, in *jsonx.Node, parents []*jsonx.Node) {
				if isBinaryDataURI(in.Str) {
					return
				}
				units = rw.leafUnits(units, inner, in, contextKey(path, parents), known, chain, depth-1-len(path))
			})
			return units
		}
	}
	if n.Str == "" {
		return units
	}
	u := &unit{text: n.Str, known: known, chain: chain}
	if key != "" {
		u.prefix = `"` + key + `": "`
	}
	return append(units, u)
}

// isBinaryDataURI reports base64 data URIs of non-text media.
func isBinaryDataURI(s string) bool {
	if !strings.HasPrefix(s, "data:") {
		return false
	}
	head, _, ok := strings.Cut(s[:min(len(s), 256)], ",")
	if !ok || !strings.HasSuffix(head, ";base64") {
		return false
	}
	mime := strings.ToLower(strings.TrimPrefix(head, "data:"))
	return !strings.HasPrefix(mime, "text/") && !strings.Contains(mime, "json") &&
		!strings.Contains(mime, "xml") && !strings.Contains(mime, "yaml") && !strings.Contains(mime, "javascript")
}

type span struct {
	start, end int
	rule       string
}

func (rw *Rewriter) replace(ctx context.Context, units []*unit, c *vault.Caller, counts map[string]int) ([]jsonx.Edit, error) {
	// A text that has already been sent goes again exactly as it went (design
	// 7.8). Its spans are frozen in the sent memo, so detection can be skipped
	// for it entirely — an agent re-sends its whole history every turn, and
	// that history is most of the request.
	spans := make([][]span, len(units))
	frozen := make([]bool, len(units))
	var texts []string
	var idx []int
	for i, u := range units {
		if f, ok := rw.Sent.Get(c.ID(), rw.Upstream, u.prefix, u.text); ok {
			spans[i], frozen[i] = fromVaultSpans(f), true
			continue
		}
		if !u.known {
			texts = append(texts, u.prefix+u.text)
			idx = append(idx, i)
		}
	}
	found := make([][]detector.Hit, len(units))
	if len(texts) > 0 {
		hits, err := rw.Detector.Scan(ctx, texts)
		if err != nil {
			return nil, fmt.Errorf("detector: %w", err)
		}
		for j, h := range hits {
			found[idx[j]] = h
		}
	}
	// Two passes: find every span, then make every placeholder. A
	// placeholder write marks the caller's known-value index dirty, and
	// rebuilding that index per unit is quadratic in the number of secrets
	// (1000 keys took 1.8 s instead of 6 ms).
	for i, u := range units {
		if !frozen[i] {
			spans[i] = rw.spans(u, found[i], c)
		}
	}
	var edits []jsonx.Edit
	for i, u := range units {
		for _, s := range spans[i] {
			value := u.text[s.start:s.end]
			ph := c.Placeholder(value)
			a, b := u.rawRange(s.start, s.end)
			edits = append(edits, jsonx.Edit{Start: a, End: b, Text: []byte(ph)})
			counts[s.rule]++
		}
	}
	return edits, nil
}

// spans merges detector hits and known-secret matches for one unit, clips
// them to the string, snaps them to rune boundaries and drops anything that
// overlaps an existing placeholder.
//
// A text that has already been sent goes again exactly as it went (design
// 7.8): its spans are frozen, so a value that only became known after this
// text left the machine never rewrites it. Only a text never sent before is
// decided afresh.
func (rw *Rewriter) spans(u *unit, hits []detector.Hit, c *vault.Caller) []span {
	var out []span
	p := len(u.prefix)
	for _, h := range hits {
		a, b := h.Start-p, h.End-p
		if b <= 0 {
			continue
		}
		out = append(out, span{max(a, 0), b, h.RuleID})
	}
	for _, r := range c.FindKnown(u.text) {
		out = append(out, span{r.Start, r.End, "known"})
	}
	phs := vault.FindPlaceholders(u.text)
	minLen := rw.MinLength
	if minLen <= 0 {
		minLen = 8
	}
	var kept []span
	for _, s := range out {
		s.start, s.end = snap(u.text, s.start, s.end)
		if s.end-s.start < minLen || overlapsAny(s, phs) {
			continue
		}
		// A rule that matches on context also matches code, paths,
		// versions and moments; masking those breaks the agent and costs a
		// cache rebuild for nothing (design 4.3.1).
		if veto.Reject(u.text, s.start, s.end) {
			continue
		}
		kept = append(kept, s)
	}
	kept = mergeSpans(kept)
	rw.Sent.Put(c.ID(), rw.Upstream, u.prefix, u.text, toVaultSpans(kept))
	return kept
}

func toVaultSpans(in []span) []vault.Span {
	if len(in) == 0 {
		return nil
	}
	out := make([]vault.Span, len(in))
	for i, s := range in {
		out[i] = vault.Span{Start: s.start, End: s.end, Rule: s.rule}
	}
	return out
}

func fromVaultSpans(in []vault.Span) []span {
	if len(in) == 0 {
		return nil
	}
	out := make([]span, len(in))
	for i, s := range in {
		out[i] = span{start: s.Start, end: s.End, rule: s.Rule}
	}
	return out
}

func snap(s string, a, b int) (int, int) {
	for a > 0 && !utf8.RuneStart(s[a]) {
		a--
	}
	for b < len(s) && !utf8.RuneStart(s[b]) {
		b++
	}
	return a, b
}

func overlapsAny(s span, phs [][]int) bool {
	for _, p := range phs {
		if s.start < p[1] && p[0] < s.end {
			return true
		}
	}
	return false
}

func mergeSpans(in []span) []span {
	if len(in) < 2 {
		return in
	}
	// Insertion sort: spans per string are few.
	for i := 1; i < len(in); i++ {
		for j := i; j > 0 && (in[j].start < in[j-1].start || in[j].start == in[j-1].start && in[j].end > in[j-1].end); j-- {
			in[j], in[j-1] = in[j-1], in[j]
		}
	}
	out := in[:1]
	for _, s := range in[1:] {
		last := &out[len(out)-1]
		if s.start < last.end {
			if s.end > last.end {
				last.end = s.end
			}
			if last.rule == "known" {
				last.rule = s.rule
			}
			continue
		}
		out = append(out, s)
	}
	return out
}
