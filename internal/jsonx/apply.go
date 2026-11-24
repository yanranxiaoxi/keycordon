package jsonx

import (
	"fmt"
	"slices"
)

// Edit replaces Raw[Start:End] with Text.
type Edit struct {
	Start, End int
	Text       []byte
}

// Apply returns raw with edits applied. Edits must not overlap; an
// insertion (Start == End) may share a position with nothing else.
// When edits is empty, raw itself is returned.
func Apply(raw []byte, edits []Edit) ([]byte, error) {
	if len(edits) == 0 {
		return raw, nil
	}
	edits = slices.Clone(edits)
	slices.SortStableFunc(edits, func(a, b Edit) int {
		if a.Start != b.Start {
			return a.Start - b.Start
		}
		return a.End - b.End
	})
	size := len(raw)
	for i, e := range edits {
		if e.Start < 0 || e.End > len(raw) || e.Start > e.End {
			return nil, fmt.Errorf("jsonx: edit %d out of range", i)
		}
		if i > 0 && e.Start < edits[i-1].End {
			return nil, fmt.Errorf("jsonx: overlapping edits at %d", e.Start)
		}
		size += len(e.Text) - (e.End - e.Start)
	}
	out := make([]byte, 0, size)
	prev := 0
	for _, e := range edits {
		out = append(out, raw[prev:e.Start]...)
		out = append(out, e.Text...)
		prev = e.End
	}
	return append(out, raw[prev:]...), nil
}
