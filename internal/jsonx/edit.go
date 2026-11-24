package jsonx

// RawRange maps the decoded byte range [from, to) of a String node to an
// absolute byte range in the raw document. Ranges that cut through an escape
// sequence are widened to cover the whole sequence.
func (d *Doc) RawRange(n *Node, from, to int) (int, int) {
	bodyStart := n.Start + 1
	if !n.escaped {
		return bodyStart + from, bodyStart + to
	}
	var spans []span
	decodeBody(d.Raw[bodyStart:n.End-1], &spans)
	if from >= len(spans) {
		return n.End - 1, n.End - 1
	}
	if to > len(spans) {
		to = len(spans)
	}
	if to <= from {
		s := bodyStart + int(spans[from].start)
		return s, s
	}
	return bodyStart + int(spans[from].start), bodyStart + int(spans[to-1].end)
}

// RawBody returns the raw (still escaped) bytes between a String node's quotes.
func (d *Doc) RawBody(n *Node) []byte {
	return d.Raw[n.Start+1 : n.End-1]
}

// AppendEscaped appends s to dst as the body of a JSON string (no quotes).
// Only characters that JSON requires to be escaped are escaped, so the
// output of a placeholder made of [A-Za-z0-9_<>] is byte-identical to its
// input. That keeps rewritten requests stable across turns.
func AppendEscaped(dst []byte, s string) []byte {
	const hex = "0123456789abcdef"
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			dst = append(dst, '\\', c)
		case c == '\n':
			dst = append(dst, '\\', 'n')
		case c == '\r':
			dst = append(dst, '\\', 'r')
		case c == '\t':
			dst = append(dst, '\\', 't')
		case c < 0x20:
			dst = append(dst, '\\', 'u', '0', '0', hex[c>>4], hex[c&0xF])
		default:
			dst = append(dst, c)
		}
	}
	return dst
}

// Walk calls fn for every String leaf (object values and array elements, not
// keys) with its path. Paths are built from object keys and "[]" for array
// elements, e.g. ["messages", "[]", "content"]. parents[i] is the container
// that path[i] indexes into. fn must not retain path or parents.
func Walk(root *Node, fn func(path []string, n *Node, parents []*Node)) {
	var path []string
	var parents []*Node
	var rec func(n *Node)
	rec = func(n *Node) {
		switch n.Kind {
		case String:
			fn(path, n, parents)
		case Object:
			parents = append(parents, n)
			for _, m := range n.Members {
				path = append(path, m.Key)
				rec(m.Value)
				path = path[:len(path)-1]
			}
			parents = parents[:len(parents)-1]
		case Array:
			parents = append(parents, n)
			for _, e := range n.Elems {
				path = append(path, "[]")
				rec(e)
				path = path[:len(path)-1]
			}
			parents = parents[:len(parents)-1]
		}
	}
	rec(root)
}
