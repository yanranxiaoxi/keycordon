package vault

import (
	"container/list"
	"crypto/sha256"
	"encoding/binary"
	"sync"
)

// Span is a byte range in a scanned string, with the rule that found it.
type Span struct {
	Start, End int
	Rule       string
}

// Sent remembers the spans a text was first sent with, per caller and
// upstream, so a value that becomes known later never rewrites history.
//
// A value is masked because a rule recognised its context, and the rules
// and the vault both change: a value sent as written in turn 1 (no
// context) is recognised in turn 2 (a new message gives it one), and the
// known-value rescan then finds it in turn 1's history too. Masking it
// there changes bytes the upstream has already seen — no security gain,
// since it saw the plaintext — and rebuilds the whole prompt cache from
// that point (design 7.8).
//
// So a text that has been sent goes again exactly as it went. Only a text
// never sent before is decided afresh. The key includes the upstream, so
// changing the upstream re-decides: that plaintext never reached the new
// one.
type Sent struct {
	mu      sync.Mutex
	entries map[[32]byte]*sentEntry
	lru     *list.List
	max     int
}

type sentEntry struct {
	key   [32]byte
	spans []Span
	elem  *list.Element
}

// MinSentText is the shortest text remembered: the detector's own minimum
// value length, below which no secret can be found and freezing is
// pointless. A text this short is also no prompt prefix worth protecting.
const MinSentText = 8

// NewSent creates a memo holding at most max texts.
func NewSent(max int) *Sent {
	if max <= 0 {
		max = 1 << 16
	}
	return &Sent{entries: map[[32]byte]*sentEntry{}, lru: list.New(), max: max}
}

func sentKey(callerID, upstream, prefix, text string) [32]byte {
	h := sha256.New()
	var n [8]byte
	for _, s := range []string{callerID, upstream, prefix, text} {
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	var k [32]byte
	h.Sum(k[:0])
	return k
}

// Get returns the spans text was first sent with.
func (s *Sent) Get(callerID, upstream, prefix, text string) ([]Span, bool) {
	if s == nil || len(text) < MinSentText {
		return nil, false
	}
	k := sentKey(callerID, upstream, prefix, text)
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entries[k]
	if e == nil {
		return nil, false
	}
	s.lru.MoveToFront(e.elem)
	return e.spans, true
}

// Put records the spans text went with.
func (s *Sent) Put(callerID, upstream, prefix, text string, spans []Span) {
	if s == nil || len(text) < MinSentText {
		return
	}
	k := sentKey(callerID, upstream, prefix, text)
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.entries[k]; e != nil {
		e.spans = spans
		s.lru.MoveToFront(e.elem)
		return
	}
	e := &sentEntry{key: k, spans: spans}
	e.elem = s.lru.PushFront(e)
	s.entries[k] = e
	for s.lru.Len() > s.max {
		old := s.lru.Back()
		if old == nil {
			break
		}
		s.lru.Remove(old)
		delete(s.entries, old.Value.(*sentEntry).key)
	}
}

// Len returns the number of remembered texts.
func (s *Sent) Len() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}
