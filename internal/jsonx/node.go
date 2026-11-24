// Package jsonx parses JSON while keeping the byte range of every value, so
// callers can rewrite individual strings without re-serializing the document.
// Re-serializing would reorder keys, drop whitespace and change number and
// escape formatting, which breaks provider prompt caches.
package jsonx

import (
	"errors"
	"fmt"
)

// Kind is the JSON type of a Node.
type Kind uint8

const (
	Null Kind = iota
	Bool
	Number
	String
	Array
	Object
)

// Node is one JSON value. Start and End are byte offsets into the parsed
// input; for strings they include the surrounding quotes.
type Node struct {
	Kind       Kind
	Start, End int
	// Str is the decoded value of a String node, or the literal source text
	// of a Number, Bool or Null node.
	Str string
	// Members holds object members in source order, including duplicates.
	Members []Member
	// Elems holds array elements in source order.
	Elems []*Node
	// escaped reports that the raw string body contains escape sequences.
	escaped bool
}

// Member is one object member.
type Member struct {
	Key   string
	Value *Node
}

// Get returns the last member with key, matching how most decoders resolve
// duplicate keys.
func (n *Node) Get(key string) *Node {
	if n == nil || n.Kind != Object {
		return nil
	}
	for i := len(n.Members) - 1; i >= 0; i-- {
		if n.Members[i].Key == key {
			return n.Members[i].Value
		}
	}
	return nil
}

// GetString returns the decoded string member with key, or "".
func (n *Node) GetString(key string) string {
	if v := n.Get(key); v != nil && v.Kind == String {
		return v.Str
	}
	return ""
}

// Escaped reports whether a String node's raw form contains escapes.
func (n *Node) Escaped() bool { return n.escaped }

// Doc is a parsed document.
type Doc struct {
	Raw  []byte
	Root *Node
	// DuplicateKeys is set when any object repeats a key. Different decoders
	// keep different copies, so callers must not trust key-based exemptions.
	DuplicateKeys bool
}

// ErrTooDeep is returned when nesting exceeds the configured limit.
var ErrTooDeep = errors.New("jsonx: nesting too deep")

// SyntaxError reports malformed JSON.
type SyntaxError struct {
	Offset int
	Msg    string
}

func (e *SyntaxError) Error() string {
	return fmt.Sprintf("jsonx: offset %d: %s", e.Offset, e.Msg)
}
