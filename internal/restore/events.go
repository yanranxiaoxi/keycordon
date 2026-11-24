package restore

import (
	"strconv"
	"strings"

	"gitlab.soraharu.com/XiaoXi/keycordon/internal/jsonx"
	"gitlab.soraharu.com/XiaoXi/keycordon/internal/protocol"
	"gitlab.soraharu.com/XiaoXi/keycordon/internal/vault"
)

// maxQueue bounds how many events may wait behind an unresolved tail.
const maxQueue = 32

// item is one unit of output: either raw bytes or a parsed event.
type item struct {
	raw []byte
	ev  *event
}

// event is a parsed JSON payload (an SSE data field or a stream element).
type event struct {
	doc        *jsonx.Doc
	vals       map[*jsonx.Node]string
	unresolved int
	// render produces the output bytes given the (possibly edited) JSON.
	render func(data []byte, changed bool) []byte
}

func (e *event) value(n *jsonx.Node) string {
	if v, ok := e.vals[n]; ok {
		return v
	}
	return n.Str
}

func (e *event) set(n *jsonx.Node, v string) {
	if e.vals == nil {
		e.vals = map[*jsonx.Node]string{}
	}
	e.vals[n] = v
}

func (e *event) bytes() []byte {
	if len(e.vals) == 0 {
		return e.render(e.doc.Raw, false)
	}
	edits := make([]jsonx.Edit, 0, len(e.vals))
	changed := false
	for n, v := range e.vals {
		if v == n.Str {
			continue
		}
		edits = append(edits, stringEdit(n, v))
		changed = true
	}
	if !changed {
		return e.render(e.doc.Raw, false)
	}
	out, err := jsonx.Apply(e.doc.Raw, edits)
	if err != nil {
		return e.render(e.doc.Raw, false)
	}
	return e.render(out, true)
}

// tail is the unrestored end of a delta that may be the start of a
// placeholder split across events.
type tail struct {
	ev   *event
	node *jsonx.Node
	text string
}

// processor restores streamed events in order. When a delta ends with
// something that could be the start of a placeholder, the whole event is
// held until the next delta of the same stream arrives; the held characters
// then move into that event. If no continuation arrives, the held event is
// emitted unchanged, so no event ever has to be invented.
type processor struct {
	a     *protocol.Adapter
	l     Lookup
	queue []item
	tails map[string]*tail
	emit  func([]byte) error
}

func newProcessor(a *protocol.Adapter, l Lookup, emit func([]byte) error) *processor {
	return &processor{a: a, l: l, tails: map[string]*tail{}, emit: emit}
}

// raw queues bytes that are not an event.
func (p *processor) raw(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	p.queue = append(p.queue, item{raw: b})
	return p.drain()
}

// event processes one JSON payload. name is the SSE event name, if any.
func (p *processor) event(doc *jsonx.Doc, name string, render func([]byte, bool) []byte) error {
	ev := &event{doc: doc, render: render}
	typ := name
	if typ == "" {
		typ = doc.Root.GetString("type")
	}
	jsonx.Walk(doc.Root, func(path []string, n *jsonx.Node, parents []*jsonx.Node) {
		if p.a.Skip.Match(path, parents, n) {
			return
		}
		di := -1
		for i, d := range p.a.Deltas {
			if (d.Event == "" || d.Event == typ || d.Event == name) && d.Field.Match(path, parents, n) {
				di = i
				break
			}
		}
		if di < 0 {
			if v, ok := leaf(p.l, n.Str); ok {
				ev.set(n, v)
			}
			return
		}
		kind := p.a.Deltas[di].Kind
		if kind == protocol.KindReasoning {
			return
		}
		key := p.streamKey(di, doc.Root, path, parents, n)
		text := n.Str
		if t := p.tails[key]; t != nil {
			prev := t.ev.value(t.node)
			t.ev.set(t.node, prev[:len(prev)-len(t.text)])
			t.ev.unresolved--
			text = t.text + text
			delete(p.tails, key)
		}
		out, held := streamText(p.l, text, kind == protocol.KindJSONFragment)
		if out != n.Str {
			ev.set(n, out)
		}
		if held != "" {
			p.tails[key] = &tail{ev: ev, node: n, text: held}
			ev.unresolved++
		}
	})
	p.queue = append(p.queue, item{ev: ev})
	if p.a.EndEvents[typ] || (name != "" && p.a.EndEvents[name]) || len(p.queue) > maxQueue {
		return p.flush()
	}
	return p.drain()
}

// streamText restores complete placeholders and returns the unrestored
// suffix that may still grow into a placeholder.
func streamText(l Lookup, s string, jsonEscape bool) (out, held string) {
	locs := vault.FindPlaceholders(s)
	rest := s
	if len(locs) > 0 {
		last := locs[len(locs)-1][1]
		head, _ := Text(l, s[:last], jsonEscape)
		rest = s[last:]
		out = head
	}
	if h := vault.PendingTail(rest); h > 0 {
		held = rest[len(rest)-h:]
	}
	return out + rest, held
}

// streamKey identifies the logical stream a delta belongs to: the delta
// rule, the concrete path (array positions replaced by the element's
// "index" member when it has one) and the adapter's root stream keys.
func (p *processor) streamKey(di int, root *jsonx.Node, path []string, parents []*jsonx.Node, n *jsonx.Node) string {
	var b strings.Builder
	b.WriteString(strconv.Itoa(di))
	for i, seg := range path {
		b.WriteByte('/')
		if seg != "[]" {
			b.WriteString(seg)
			continue
		}
		child := n
		if i+1 < len(parents) {
			child = parents[i+1]
		}
		if idx := child.Get("index"); idx != nil && idx.Kind == jsonx.Number {
			b.WriteString("#" + idx.Str)
			continue
		}
		for j, e := range parents[i].Elems {
			if e == child {
				b.WriteString(strconv.Itoa(j))
				break
			}
		}
	}
	for _, k := range p.a.StreamKeys {
		if v := root.Get(k); v != nil {
			b.WriteString("|" + k + "=" + v.Str)
		}
	}
	return b.String()
}

// drain emits queued items up to the first event with an unresolved tail.
func (p *processor) drain() error {
	i := 0
	for ; i < len(p.queue); i++ {
		it := p.queue[i]
		if it.ev != nil && it.ev.unresolved > 0 {
			break
		}
		if err := p.write(it); err != nil {
			return err
		}
	}
	p.queue = p.queue[i:]
	return nil
}

// flush emits everything, leaving held tails in their original events.
func (p *processor) flush() error {
	clear(p.tails)
	for _, it := range p.queue {
		if it.ev != nil {
			it.ev.unresolved = 0
		}
	}
	return p.drain()
}

func (p *processor) write(it item) error {
	if it.ev != nil {
		return p.emit(it.ev.bytes())
	}
	return p.emit(it.raw)
}
