// Package pathpat matches JSON leaf paths against simple patterns used by
// protocol adapters.
//
// A pattern is a dot-separated list of segments:
//
//	name        an object key
//	*           any single key or array element
//	[]          any array element
//	**          zero or more segments
//	prefix*     a key starting with prefix (suffix* for a suffix)
//	*suffix     a key ending with suffix
//	?k=v        zero-width: the node at this depth is an object whose member
//	            k has the literal or string value v
//	?k!=v       same, but k is absent or differs from v
//	?k          the object has member k
//
// Example: "**.?type=thinking.thinking" matches the "thinking" string of any
// object whose "type" is "thinking".
package pathpat

import (
	"fmt"
	"strings"

	"gitlab.soraharu.com/XiaoXi/keycordon/internal/jsonx"
)

type segKind uint8

const (
	segKey segKind = iota
	segAny
	segElem
	segDeep
	segPred
	segGlob
)

type seg struct {
	kind   segKind
	key    string
	pk, pv string
	op     byte // '=', '!', 'e' (exists)
	// glob is a key pattern with one '*': prefix and suffix around it.
	prefix, suffix string
}

// Pattern is a compiled path pattern.
type Pattern struct {
	src  string
	segs []seg
}

func (p *Pattern) String() string { return p.src }

// Compile parses a pattern. A leading "$." or "$" is accepted and ignored.
func Compile(src string) (*Pattern, error) {
	s := strings.TrimPrefix(strings.TrimPrefix(src, "$"), ".")
	if s == "" {
		return nil, fmt.Errorf("pathpat: empty pattern %q", src)
	}
	p := &Pattern{src: src}
	for _, part := range strings.Split(s, ".") {
		switch {
		case part == "":
			return nil, fmt.Errorf("pathpat: empty segment in %q", src)
		case part == "*":
			p.segs = append(p.segs, seg{kind: segAny})
		case part == "[]":
			p.segs = append(p.segs, seg{kind: segElem})
		case part == "**":
			p.segs = append(p.segs, seg{kind: segDeep})
		case strings.Contains(part, "*"):
			// A key pattern with one '*': prefix*suffix. A lone '*' is
			// handled above, and '**' is a whole segment.
			pre, suf, ok := strings.Cut(part, "*")
			if !ok || strings.Contains(suf, "*") {
				return nil, fmt.Errorf("pathpat: %q: at most one * per segment", src)
			}
			p.segs = append(p.segs, seg{kind: segGlob, prefix: pre, suffix: suf})
		case part[0] == '?':
			sg, err := parsePred(part[1:])
			if err != nil {
				return nil, fmt.Errorf("pathpat: %q: %w", src, err)
			}
			p.segs = append(p.segs, sg)
		default:
			p.segs = append(p.segs, seg{kind: segKey, key: part})
		}
	}
	return p, nil
}

// MustCompile is Compile that panics on error.
func MustCompile(src string) *Pattern {
	p, err := Compile(src)
	if err != nil {
		panic(err)
	}
	return p
}

func parsePred(s string) (seg, error) {
	if i := strings.Index(s, "!="); i > 0 {
		return seg{kind: segPred, pk: s[:i], pv: s[i+2:], op: '!'}, nil
	}
	if i := strings.IndexByte(s, '='); i > 0 {
		return seg{kind: segPred, pk: s[:i], pv: s[i+1:], op: '='}, nil
	}
	if s == "" {
		return seg{}, fmt.Errorf("empty predicate")
	}
	return seg{kind: segPred, pk: s, op: 'e'}, nil
}

// Match reports whether the leaf at path matches. parents[i] is the
// container that path[i] indexes into, as produced by jsonx.Walk.
func (p *Pattern) Match(path []string, parents []*jsonx.Node, leaf *jsonx.Node) bool {
	return p.match(0, 0, path, parents, leaf)
}

// MatchPrefix reports whether the pattern matches path or any ancestor of
// path, so a pattern naming an object or array also covers its contents.
func (p *Pattern) MatchPrefix(path []string, parents []*jsonx.Node, leaf *jsonx.Node) bool {
	for n := len(path); n >= 0; n-- {
		var node *jsonx.Node
		if n == len(path) {
			node = leaf
		} else {
			node = parents[n]
		}
		if p.match(0, 0, path[:n], parents[:n], node) {
			return true
		}
	}
	return false
}

func nodeAt(d int, parents []*jsonx.Node, leaf *jsonx.Node) *jsonx.Node {
	if d < len(parents) {
		return parents[d]
	}
	return leaf
}

func (p *Pattern) match(si, d int, path []string, parents []*jsonx.Node, leaf *jsonx.Node) bool {
	if si == len(p.segs) {
		return d == len(path)
	}
	sg := p.segs[si]
	switch sg.kind {
	case segPred:
		return predOK(sg, nodeAt(d, parents, leaf)) && p.match(si+1, d, path, parents, leaf)
	case segDeep:
		for k := d; k <= len(path); k++ {
			if p.match(si+1, k, path, parents, leaf) {
				return true
			}
		}
		return false
	}
	if d >= len(path) {
		return false
	}
	isElem := parents[d].Kind == jsonx.Array
	switch sg.kind {
	case segKey:
		if isElem || path[d] != sg.key {
			return false
		}
	case segElem:
		if !isElem {
			return false
		}
	case segGlob:
		if isElem || !strings.HasPrefix(path[d], sg.prefix) || !strings.HasSuffix(path[d], sg.suffix) {
			return false
		}
	}
	return p.match(si+1, d+1, path, parents, leaf)
}

func predOK(sg seg, n *jsonx.Node) bool {
	if n == nil || n.Kind != jsonx.Object {
		return sg.op == '!'
	}
	v := n.Get(sg.pk)
	switch sg.op {
	case 'e':
		return v != nil
	case '=':
		return v != nil && v.Kind != jsonx.Object && v.Kind != jsonx.Array && v.Str == sg.pv
	default:
		return v == nil || v.Kind == jsonx.Object || v.Kind == jsonx.Array || v.Str != sg.pv
	}
}

// Set is a list of patterns.
type Set []*Pattern

// CompileSet compiles every pattern in srcs.
func CompileSet(srcs []string) (Set, error) {
	out := make(Set, 0, len(srcs))
	for _, s := range srcs {
		p, err := Compile(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// Match reports whether any pattern matches the leaf or one of its ancestors.
func (s Set) Match(path []string, parents []*jsonx.Node, leaf *jsonx.Node) bool {
	for _, p := range s {
		if p.MatchPrefix(path, parents, leaf) {
			return true
		}
	}
	return false
}
