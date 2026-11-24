// Package restore turns placeholders in AI responses back into the original
// secrets, for complete JSON bodies and for SSE / JSON-array / NDJSON
// streams. It never calls the detector. Errors fail open: a placeholder that
// cannot be restored is passed through unchanged, which never leaks data.
package restore

import (
	"bytes"
	"strings"

	"gitlab.soraharu.com/XiaoXi/keycordon/internal/jsonx"
	"gitlab.soraharu.com/XiaoXi/keycordon/internal/protocol"
	"gitlab.soraharu.com/XiaoXi/keycordon/internal/vault"
)

// Marker is the byte string every placeholder contains even when its '<'
// is JSON-escaped; bodies without it are never parsed.
var Marker = []byte("SECRET_")

// Lookup resolves a placeholder.
type Lookup interface {
	Restore(placeholder string) (string, bool)
}

var _ Lookup = (*vault.Caller)(nil)

// Text replaces complete placeholders in s. When jsonEscape is set the
// secrets are written as JSON string content.
func Text(l Lookup, s string, jsonEscape bool) (string, bool) {
	locs := vault.FindPlaceholders(s)
	if len(locs) == 0 {
		return s, false
	}
	var b strings.Builder
	last, changed := 0, false
	for _, loc := range locs {
		b.WriteString(s[last:loc[0]])
		if v, ok := l.Restore(s[loc[0]:loc[1]]); ok {
			if jsonEscape {
				b.Write(jsonx.AppendEscaped(nil, v))
			} else {
				b.WriteString(v)
			}
			changed = true
		} else {
			b.WriteString(s[loc[0]:loc[1]])
		}
		last = loc[1]
	}
	if !changed {
		return s, false
	}
	b.WriteString(s[last:])
	return b.String(), true
}

// Bytes restores placeholders in a non-JSON body.
func Bytes(l Lookup, body []byte) []byte {
	if !bytes.Contains(body, Marker) {
		return body
	}
	out, changed := Text(l, string(body), false)
	if !changed {
		return body
	}
	return []byte(out)
}

// looksLikeJSON reports strings that hold a JSON document (tool arguments);
// secrets restored into them must be JSON-escaped.
func looksLikeJSON(s string) bool {
	t := strings.TrimSpace(s)
	if len(t) < 2 || !(t[0] == '{' && t[len(t)-1] == '}' || t[0] == '[' && t[len(t)-1] == ']') {
		return false
	}
	_, err := jsonx.Parse([]byte(t), 256)
	return err == nil
}

// leaf restores one complete string value.
func leaf(l Lookup, s string) (string, bool) {
	if !strings.Contains(s, vault.PlaceholderMarker) {
		return s, false
	}
	return Text(l, s, looksLikeJSON(s))
}

// JSON restores every string of a complete JSON body except those matched
// by the adapter's skip list. The input is returned unchanged when nothing
// was restored or the body is not valid JSON (then Bytes is applied).
func JSON(a *protocol.Adapter, l Lookup, body []byte) []byte {
	if !bytes.Contains(body, Marker) {
		return body
	}
	doc, err := jsonx.Parse(body, 512)
	if err != nil {
		return Bytes(l, body)
	}
	var edits []jsonx.Edit
	jsonx.Walk(doc.Root, func(path []string, n *jsonx.Node, parents []*jsonx.Node) {
		if a != nil && a.Skip.Match(path, parents, n) {
			return
		}
		if v, ok := leaf(l, n.Str); ok {
			edits = append(edits, stringEdit(n, v))
		}
	})
	out, err := jsonx.Apply(body, edits)
	if err != nil {
		return body
	}
	return out
}

func stringEdit(n *jsonx.Node, v string) jsonx.Edit {
	return jsonx.Edit{Start: n.Start + 1, End: n.End - 1, Text: jsonx.AppendEscaped(nil, v)}
}
