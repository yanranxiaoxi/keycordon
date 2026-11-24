package jsonx

import (
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

func (p *parser) str() (*Node, error) {
	start := p.pos
	p.pos++ // opening quote
	bodyStart := p.pos
	escaped := false
	for {
		if p.pos >= len(p.buf) {
			return nil, p.errf("unterminated string")
		}
		c := p.buf[p.pos]
		if c == '"' {
			break
		}
		if c < 0x20 {
			return nil, p.errf("control character in string")
		}
		if c == '\\' {
			escaped = true
			if p.pos+1 >= len(p.buf) {
				return nil, p.errf("unterminated escape")
			}
			switch p.buf[p.pos+1] {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				p.pos += 2
			case 'u':
				if p.pos+6 > len(p.buf) || !isHex4(p.buf[p.pos+2:p.pos+6]) {
					return nil, p.errf("invalid \\u escape")
				}
				p.pos += 6
			default:
				return nil, p.errf("invalid escape")
			}
			continue
		}
		p.pos++
	}
	body := p.buf[bodyStart:p.pos]
	p.pos++ // closing quote
	n := &Node{Kind: String, Start: start, End: p.pos, escaped: escaped}
	if escaped {
		n.Str = decodeBody(body, nil)
	} else {
		n.Str = string(body)
	}
	return n, nil
}

func isHex4(b []byte) bool {
	for _, c := range b {
		if hexVal(c) < 0 {
			return false
		}
	}
	return true
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

func hex4(b []byte) rune {
	return rune(hexVal(b[0])<<12 | hexVal(b[1])<<8 | hexVal(b[2])<<4 | hexVal(b[3]))
}

// span maps one decoded byte to the raw escape unit that produced it.
type span struct{ start, end int32 }

// decodeBody decodes a validated string body. When spans is non-nil, it
// receives one entry per decoded byte giving the raw unit's body offsets.
func decodeBody(body []byte, spans *[]span) string {
	var sb strings.Builder
	sb.Grow(len(body))
	emit := func(s string, rs, re int) {
		sb.WriteString(s)
		if spans != nil {
			for range len(s) {
				*spans = append(*spans, span{int32(rs), int32(re)})
			}
		}
	}
	for i := 0; i < len(body); {
		c := body[i]
		if c != '\\' {
			_, size := utf8.DecodeRune(body[i:])
			emit(string(body[i:i+size]), i, i+size)
			i += size
			continue
		}
		switch body[i+1] {
		case 'u':
			r := hex4(body[i+2 : i+6])
			end := i + 6
			if utf16.IsSurrogate(r) && end+6 <= len(body) && body[end] == '\\' && body[end+1] == 'u' {
				if r2 := hex4(body[end+2 : end+6]); utf16.DecodeRune(r, r2) != utf8.RuneError {
					r = utf16.DecodeRune(r, r2)
					end += 6
				}
			}
			emit(string(r), i, end)
			i = end
		default:
			emit(string(unescapeChar(body[i+1])), i, i+2)
			i += 2
		}
	}
	return sb.String()
}

func unescapeChar(c byte) byte {
	switch c {
	case 'b':
		return '\b'
	case 'f':
		return '\f'
	case 'n':
		return '\n'
	case 'r':
		return '\r'
	case 't':
		return '\t'
	}
	return c // '"', '\\', '/'
}
