package jsonx

// Parse parses raw. maxDepth bounds container nesting; zero means 512.
// A leading UTF-8 byte-order mark is tolerated; offsets stay absolute.
func Parse(raw []byte, maxDepth int) (*Doc, error) {
	if maxDepth <= 0 {
		maxDepth = 512
	}
	p := &parser{buf: raw, maxDepth: maxDepth}
	if len(raw) >= 3 && raw[0] == 0xEF && raw[1] == 0xBB && raw[2] == 0xBF {
		p.pos = 3
	}
	p.skipWS()
	root, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.skipWS()
	if p.pos != len(p.buf) {
		return nil, p.errf("trailing data after top-level value")
	}
	return &Doc{Raw: raw, Root: root, DuplicateKeys: p.dup}, nil
}

type parser struct {
	buf      []byte
	pos      int
	maxDepth int
	dup      bool
}

func (p *parser) errf(msg string) error {
	return &SyntaxError{Offset: p.pos, Msg: msg}
}

func (p *parser) skipWS() {
	for p.pos < len(p.buf) {
		switch p.buf[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *parser) value(depth int) (*Node, error) {
	if p.pos >= len(p.buf) {
		return nil, p.errf("unexpected end of input")
	}
	switch c := p.buf[p.pos]; {
	case c == '{':
		return p.object(depth + 1)
	case c == '[':
		return p.array(depth + 1)
	case c == '"':
		return p.str()
	case c == 't':
		return p.literal("true", Bool)
	case c == 'f':
		return p.literal("false", Bool)
	case c == 'n':
		return p.literal("null", Null)
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	default:
		return nil, p.errf("unexpected character")
	}
}

func (p *parser) literal(word string, kind Kind) (*Node, error) {
	end := p.pos + len(word)
	if end > len(p.buf) || string(p.buf[p.pos:end]) != word {
		return nil, p.errf("invalid literal")
	}
	n := &Node{Kind: kind, Start: p.pos, End: end, Str: word}
	p.pos = end
	return n, nil
}

func (p *parser) digits() int {
	s := p.pos
	for p.pos < len(p.buf) && p.buf[p.pos] >= '0' && p.buf[p.pos] <= '9' {
		p.pos++
	}
	return p.pos - s
}

func (p *parser) number() (*Node, error) {
	start := p.pos
	if p.buf[p.pos] == '-' {
		p.pos++
	}
	if p.digits() == 0 {
		return nil, p.errf("invalid number")
	}
	if p.pos < len(p.buf) && p.buf[p.pos] == '.' {
		p.pos++
		if p.digits() == 0 {
			return nil, p.errf("invalid number")
		}
	}
	if p.pos < len(p.buf) && (p.buf[p.pos] == 'e' || p.buf[p.pos] == 'E') {
		p.pos++
		if p.pos < len(p.buf) && (p.buf[p.pos] == '+' || p.buf[p.pos] == '-') {
			p.pos++
		}
		if p.digits() == 0 {
			return nil, p.errf("invalid number")
		}
	}
	return &Node{Kind: Number, Start: start, End: p.pos, Str: string(p.buf[start:p.pos])}, nil
}
