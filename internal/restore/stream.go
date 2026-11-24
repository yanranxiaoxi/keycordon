package restore

import (
	"bytes"
	"errors"
	"io"

	"gitlab.soraharu.com/XiaoXi/keycordon/internal/jsonx"
	"gitlab.soraharu.com/XiaoXi/keycordon/internal/protocol"
)

// maxEvent bounds a single buffered SSE event or stream element. Larger
// ones are passed through unchanged.
const maxEvent = 16 << 20

// Stream is an io.WriteCloser that restores a response stream and writes
// the result to the destination, calling flush after each output chunk.
type Stream interface {
	io.WriteCloser
}

type output struct {
	w     io.Writer
	flush func()
}

func (o *output) emit(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	if _, err := o.w.Write(b); err != nil {
		return err
	}
	if o.flush != nil {
		o.flush()
	}
	return nil
}

// ---- SSE ----

type sseStream struct {
	out  *output
	p    *processor
	buf  []byte
	l    Lookup
	done bool
}

// NewSSE returns a writer that restores a text/event-stream body.
func NewSSE(a *protocol.Adapter, l Lookup, w io.Writer, flush func()) Stream {
	s := &sseStream{out: &output{w: w, flush: flush}, l: l}
	s.p = newProcessor(a, l, s.out.emit)
	return s
}

func (s *sseStream) Write(b []byte) (int, error) {
	if s.done {
		return 0, errors.New("restore: write after close")
	}
	s.buf = append(s.buf, b...)
	for {
		end := eventEnd(s.buf)
		if end < 0 {
			break
		}
		ev := s.buf[:end]
		s.buf = s.buf[end:]
		if err := s.handle(ev); err != nil {
			return len(b), err
		}
	}
	if len(s.buf) > maxEvent {
		if err := s.p.flush(); err != nil {
			return len(b), err
		}
		if err := s.out.emit(s.buf); err != nil {
			return len(b), err
		}
		s.buf = nil
	}
	return len(b), nil
}

func (s *sseStream) Close() error {
	if s.done {
		return nil
	}
	s.done = true
	if len(s.buf) > 0 {
		if err := s.handle(s.buf); err != nil {
			return err
		}
		s.buf = nil
	}
	return s.p.flush()
}

// eventEnd returns the length of the first complete event (including its
// terminating blank line) or -1. Lines may end in CRLF, LF or CR; a CR at
// the very end of the buffer is ambiguous and waits for more input.
func eventEnd(b []byte) int {
	lineStart := 0
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c != '\n' && c != '\r' {
			continue
		}
		next := i + 1
		if c == '\r' {
			if next == len(b) {
				return -1
			}
			if b[next] == '\n' {
				next++
			}
		}
		if i == lineStart {
			return next
		}
		lineStart = next
		i = next - 1
	}
	return -1
}

type sseLine struct {
	text []byte // without terminator
	term []byte
}

func splitLines(ev []byte) []sseLine {
	var lines []sseLine
	for len(ev) > 0 {
		i := bytes.IndexAny(ev, "\r\n")
		if i < 0 {
			lines = append(lines, sseLine{text: ev})
			break
		}
		n := 1
		if ev[i] == '\r' && i+1 < len(ev) && ev[i+1] == '\n' {
			n = 2
		}
		lines = append(lines, sseLine{text: ev[:i], term: ev[i : i+n]})
		ev = ev[i+n:]
	}
	return lines
}

func (s *sseStream) handle(ev []byte) error {
	lines := splitLines(ev)
	var name string
	var data [][]byte
	dataIdx := -1
	for i, ln := range lines {
		field, value, _ := bytes.Cut(ln.text, []byte(":"))
		value = bytes.TrimPrefix(value, []byte(" "))
		switch string(field) {
		case "event":
			name = string(value)
		case "data":
			if dataIdx < 0 {
				dataIdx = i
			}
			data = append(data, value)
		}
	}
	if dataIdx < 0 {
		return s.p.raw(ev)
	}
	payload := bytes.Join(data, []byte("\n"))
	if t := bytes.TrimSpace(payload); len(t) == 0 || t[0] != '{' && t[0] != '[' {
		if bytes.Equal(t, []byte("[DONE]")) {
			if err := s.p.flush(); err != nil {
				return err
			}
		}
		return s.p.raw(Bytes(s.l, ev))
	}
	doc, err := jsonx.Parse(payload, 512)
	if err != nil {
		return s.p.raw(Bytes(s.l, ev))
	}
	render := func(newData []byte, changed bool) []byte {
		if !changed {
			return ev
		}
		var out []byte
		for i, ln := range lines {
			field, _, _ := bytes.Cut(ln.text, []byte(":"))
			if string(field) == "data" {
				if i != dataIdx {
					continue
				}
				out = append(out, "data: "...)
				out = append(out, newData...)
			} else {
				out = append(out, ln.text...)
			}
			out = append(out, ln.term...)
		}
		return out
	}
	return s.p.event(doc, name, render)
}

// ---- JSON array / NDJSON ----

type seqStream struct {
	out  *output
	p    *processor
	base int

	depth  int
	inStr  bool
	esc    bool
	inElem bool
	cur    []byte
	raw    []byte
	done   bool
}

// NewJSONArray restores a streamed JSON array of objects (Gemini without
// alt=sse); each element is processed as an event.
func NewJSONArray(a *protocol.Adapter, l Lookup, w io.Writer, flush func()) Stream {
	return newSeq(a, l, w, flush, 1)
}

// NewNDJSON restores newline-delimited JSON objects (Ollama).
func NewNDJSON(a *protocol.Adapter, l Lookup, w io.Writer, flush func()) Stream {
	return newSeq(a, l, w, flush, 0)
}

func newSeq(a *protocol.Adapter, l Lookup, w io.Writer, flush func(), base int) Stream {
	s := &seqStream{out: &output{w: w, flush: flush}, base: base}
	s.p = newProcessor(a, l, s.out.emit)
	return s
}

func (s *seqStream) Write(b []byte) (int, error) {
	if s.done {
		return 0, errors.New("restore: write after close")
	}
	for _, c := range b {
		if s.inElem {
			s.cur = append(s.cur, c)
		} else {
			s.raw = append(s.raw, c)
		}
		if s.inStr {
			switch {
			case s.esc:
				s.esc = false
			case c == '\\':
				s.esc = true
			case c == '"':
				s.inStr = false
			}
			continue
		}
		switch c {
		case '"':
			s.inStr = true
		case '{', '[':
			if !s.inElem && s.depth == s.base && c == '{' {
				// Move the brace from raw into the element.
				s.raw = s.raw[:len(s.raw)-1]
				if err := s.p.raw(s.raw); err != nil {
					return len(b), err
				}
				s.raw = nil
				s.inElem = true
				s.cur = append(s.cur[:0:0], c)
			}
			s.depth++
		case '}', ']':
			s.depth--
			if s.inElem && s.depth == s.base {
				s.inElem = false
				elem := s.cur
				s.cur = nil
				if err := s.element(elem); err != nil {
					return len(b), err
				}
			}
		}
		if s.inElem && len(s.cur) > maxEvent {
			if err := s.p.flush(); err != nil {
				return len(b), err
			}
			if err := s.out.emit(s.cur); err != nil {
				return len(b), err
			}
			s.cur = nil
			s.inElem = false
			// The rest of this element is passed through as raw bytes.
		}
	}
	if !s.inElem && len(s.raw) > 0 {
		raw := s.raw
		s.raw = nil
		if err := s.p.raw(raw); err != nil {
			return len(b), err
		}
	}
	return len(b), nil
}

func (s *seqStream) element(elem []byte) error {
	doc, err := jsonx.Parse(elem, 512)
	if err != nil {
		return s.p.raw(elem)
	}
	return s.p.event(doc, "", func(data []byte, changed bool) []byte { return data })
}

func (s *seqStream) Close() error {
	if s.done {
		return nil
	}
	s.done = true
	if err := s.p.raw(append(s.cur, s.raw...)); err != nil {
		return err
	}
	return s.p.flush()
}
