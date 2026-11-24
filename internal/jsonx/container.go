package jsonx

func (p *parser) object(depth int) (*Node, error) {
	if depth > p.maxDepth {
		return nil, ErrTooDeep
	}
	n := &Node{Kind: Object, Start: p.pos}
	p.pos++ // '{'
	p.skipWS()
	if p.pos < len(p.buf) && p.buf[p.pos] == '}' {
		p.pos++
		n.End = p.pos
		return n, nil
	}
	seen := map[string]struct{}{}
	for {
		p.skipWS()
		if p.pos >= len(p.buf) || p.buf[p.pos] != '"' {
			return nil, p.errf("expected object key")
		}
		key, err := p.str()
		if err != nil {
			return nil, err
		}
		if _, ok := seen[key.Str]; ok {
			p.dup = true
		}
		seen[key.Str] = struct{}{}
		p.skipWS()
		if p.pos >= len(p.buf) || p.buf[p.pos] != ':' {
			return nil, p.errf("expected ':'")
		}
		p.pos++
		p.skipWS()
		v, err := p.value(depth)
		if err != nil {
			return nil, err
		}
		n.Members = append(n.Members, Member{Key: key.Str, Value: v})
		p.skipWS()
		if p.pos >= len(p.buf) {
			return nil, p.errf("unterminated object")
		}
		switch p.buf[p.pos] {
		case ',':
			p.pos++
		case '}':
			p.pos++
			n.End = p.pos
			return n, nil
		default:
			return nil, p.errf("expected ',' or '}'")
		}
	}
}

func (p *parser) array(depth int) (*Node, error) {
	if depth > p.maxDepth {
		return nil, ErrTooDeep
	}
	n := &Node{Kind: Array, Start: p.pos}
	p.pos++ // '['
	p.skipWS()
	if p.pos < len(p.buf) && p.buf[p.pos] == ']' {
		p.pos++
		n.End = p.pos
		return n, nil
	}
	for {
		p.skipWS()
		v, err := p.value(depth)
		if err != nil {
			return nil, err
		}
		n.Elems = append(n.Elems, v)
		p.skipWS()
		if p.pos >= len(p.buf) {
			return nil, p.errf("unterminated array")
		}
		switch p.buf[p.pos] {
		case ',':
			p.pos++
		case ']':
			p.pos++
			n.End = p.pos
			return n, nil
		default:
			return nil, p.errf("expected ',' or ']'")
		}
	}
}
