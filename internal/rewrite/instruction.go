package rewrite

import (
	"strings"

	"gitlab.soraharu.com/XiaoXi/keycordon/internal/jsonx"
	"gitlab.soraharu.com/XiaoXi/keycordon/internal/protocol"
)

// InstructionMarker starts the notice; requests that already contain it are
// not injected again (for example when two proxies are chained).
const InstructionMarker = "[keycordon/1]"

// Instruction is the fixed notice added to the system prompt. It contains no
// variable parts so it never changes the prompt prefix between requests.
const Instruction = InstructionMarker + " Some values in this conversation were replaced with placeholders such as <SECRET_TYPE_xxxxxxxx>. " +
	"Treat each placeholder as the real value and copy it exactly, including the angle brackets, whenever you need to use it " +
	"(for example in commands, code or tool arguments). Never alter, split, decode or guess a placeholder, " +
	"and do not repeat placeholders in your reasoning unless the task requires it."

func quoted(s string) []byte {
	b := []byte{'"'}
	b = jsonx.AppendEscaped(b, s)
	return append(b, '"')
}

func appendToString(n *jsonx.Node, text string) jsonx.Edit {
	sep := "\n\n"
	if n.Str == "" {
		sep = ""
	}
	return jsonx.Edit{Start: n.End - 1, End: n.End - 1, Text: jsonx.AppendEscaped(nil, sep+text)}
}

// insertFirst inserts an element at the start of an array.
func insertFirst(arr *jsonx.Node, elem []byte) jsonx.Edit {
	if len(arr.Elems) > 0 {
		elem = append(elem, ',')
	}
	return jsonx.Edit{Start: arr.Start + 1, End: arr.Start + 1, Text: elem}
}

// insertLast inserts an element at the end of an array.
func insertLast(arr *jsonx.Node, elem []byte) jsonx.Edit {
	if len(arr.Elems) > 0 {
		elem = append([]byte{','}, elem...)
	}
	return jsonx.Edit{Start: arr.End - 1, End: arr.End - 1, Text: elem}
}

// insertMember inserts a member at the start of an object.
func insertMember(obj *jsonx.Node, key string, value []byte) jsonx.Edit {
	b := quoted(key)
	b = append(b, ':')
	b = append(b, value...)
	if len(obj.Members) > 0 {
		b = append(b, ',')
	}
	return jsonx.Edit{Start: obj.Start + 1, End: obj.Start + 1, Text: b}
}

func textBlock(text string) []byte {
	b := []byte(`{"type":"text","text":`)
	b = append(b, quoted(text)...)
	return append(b, '}')
}

// target resolves "a.b|c.d": the first alternative that exists, else the
// parent object and key of the first alternative (when the parent exists).
func target(root *jsonx.Node, path string) (node, parent *jsonx.Node, key string) {
	alts := strings.Split(path, "|")
	for i, alt := range alts {
		parts := strings.Split(alt, ".")
		p := root
		for _, k := range parts[:len(parts)-1] {
			p = p.Get(k)
		}
		if p == nil || p.Kind != jsonx.Object {
			continue
		}
		last := parts[len(parts)-1]
		if n := p.Get(last); n != nil {
			return n, p, last
		}
		if i == 0 {
			parent, key = p, last
		}
	}
	return nil, parent, key
}

// instructionEdit returns the edit that adds the notice, or false when the
// body has no suitable place for it.
func instructionEdit(root *jsonx.Node, spec *protocol.InstructionSpec, text string) (jsonx.Edit, bool) {
	if root == nil || root.Kind != jsonx.Object {
		return jsonx.Edit{}, false
	}
	node, parent, key := target(root, spec.Path)
	switch spec.Strategy {
	case protocol.InstrString:
		return stringTarget(node, parent, key, text)
	case protocol.InstrStringOrBlocks:
		if node != nil && node.Kind == jsonx.Array {
			return insertLast(node, textBlock(text)), true
		}
		return stringTarget(node, parent, key, text)
	case protocol.InstrOpenAIMessages:
		if node == nil || node.Kind != jsonx.Array {
			return jsonx.Edit{}, false
		}
		if len(node.Elems) > 0 {
			first := node.Elems[0]
			if role := first.GetString("role"); role == "system" || role == "developer" {
				switch c := first.Get("content"); {
				case c != nil && c.Kind == jsonx.String:
					return appendToString(c, text), true
				case c != nil && c.Kind == jsonx.Array:
					return insertLast(c, textBlock(text)), true
				}
			}
		}
		msg := []byte(`{"role":"system","content":`)
		msg = append(msg, quoted(text)...)
		return insertFirst(node, append(msg, '}')), true
	case protocol.InstrGemini:
		part := []byte(`{"text":`)
		part = append(append(part, quoted(text)...), '}')
		if node != nil {
			if node.Kind != jsonx.Object {
				return jsonx.Edit{}, false
			}
			if parts := node.Get("parts"); parts != nil && parts.Kind == jsonx.Array {
				return insertLast(parts, part), true
			}
			if node.Get("parts") != nil {
				return jsonx.Edit{}, false
			}
			v := append([]byte(`"parts":[`), part...)
			v = append(v, ']')
			if len(node.Members) > 0 {
				v = append(v, ',')
			}
			return jsonx.Edit{Start: node.Start + 1, End: node.Start + 1, Text: v}, true
		}
		if parent == nil {
			return jsonx.Edit{}, false
		}
		v := append([]byte(`{"parts":[`), part...)
		return insertMember(parent, key, append(v, ']', '}')), true
	case protocol.InstrResponsesInput:
		if node != nil && node.Kind == jsonx.Array {
			msg := []byte(`{"type":"message","role":"developer","content":[{"type":"input_text","text":`)
			msg = append(msg, quoted(text)...)
			return insertFirst(node, append(msg, '}', ']', '}')), true
		}
		n, p, k := target(root, "instructions")
		return stringTarget(n, p, k, text)
	}
	return jsonx.Edit{}, false
}

func stringTarget(node, parent *jsonx.Node, key, text string) (jsonx.Edit, bool) {
	switch {
	case node == nil && parent != nil:
		return insertMember(parent, key, quoted(text)), true
	case node == nil:
		return jsonx.Edit{}, false
	case node.Kind == jsonx.String:
		return appendToString(node, text), true
	case node.Kind == jsonx.Null:
		return jsonx.Edit{Start: node.Start, End: node.End, Text: quoted(text)}, true
	}
	return jsonx.Edit{}, false
}
