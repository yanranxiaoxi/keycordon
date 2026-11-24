// Package vault maps secrets to deterministic placeholders and back. It keeps
// everything in memory; only the master key may live on disk.
package vault

import (
	"container/list"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rrethy/ahocorasick"
)

// Options tunes a Vault.
type Options struct {
	// MaxEntriesPerCaller bounds each caller partition (LRU). Default 10000.
	MaxEntriesPerCaller int
	// IdleTTL drops entries and callers not used for this long. Default 24h.
	IdleTTL time.Duration
	// Now overrides the clock in tests.
	Now func() time.Time
}

// Vault holds one partition per caller.
type Vault struct {
	master []byte
	opts   Options

	mu      sync.Mutex
	callers map[string]*Caller
}

// New creates a vault. master must be at least 32 bytes.
func New(master []byte, opts Options) *Vault {
	if opts.MaxEntriesPerCaller <= 0 {
		opts.MaxEntriesPerCaller = 10000
	}
	if opts.IdleTTL <= 0 {
		opts.IdleTTL = 24 * time.Hour
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Vault{master: slices.Clone(master), opts: opts, callers: map[string]*Caller{}}
}

// CallerID derives a stable, non-reversible caller ID from a credential.
func (v *Vault) CallerID(credential string) string {
	m := hmac.New(sha256.New, v.master)
	m.Write([]byte("keycordon/caller/v1\x00"))
	m.Write([]byte(credential))
	return "c" + hex.EncodeToString(m.Sum(nil))[:24]
}

// Caller returns the partition for id, creating it when needed.
func (v *Vault) Caller(id string) *Caller {
	v.mu.Lock()
	defer v.mu.Unlock()
	c := v.callers[id]
	if c == nil {
		key, err := hkdf.Key(sha256.New, v.master, nil, "keycordon/v1/"+id, 32)
		if err != nil {
			panic("vault: hkdf: " + err.Error())
		}
		c = &Caller{
			id:      id,
			key:     key,
			opts:    &v.opts,
			byPH:    map[string]*entry{},
			byValue: map[string]*entry{},
			lru:     list.New(),
		}
		v.callers[id] = c
	}
	c.touchCaller()
	return c
}

// Sweep removes idle entries and empty idle callers.
func (v *Vault) Sweep() {
	now := v.opts.Now()
	v.mu.Lock()
	defer v.mu.Unlock()
	for id, c := range v.callers {
		if c.sweep(now) == 0 && now.Sub(c.lastUsedAt()) > v.opts.IdleTTL {
			delete(v.callers, id)
		}
	}
}

// Stats returns the number of callers and entries.
func (v *Vault) Stats() (callers, entries int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, c := range v.callers {
		entries += c.Len()
	}
	return len(v.callers), entries
}

type entry struct {
	value, ph string
	elem      *list.Element
	used      time.Time
}

// Caller is one isolated partition. Placeholders created for one caller can
// never be restored through another.
type Caller struct {
	id   string
	key  []byte
	opts *Options

	mu       sync.Mutex
	byPH     map[string]*entry
	byValue  map[string]*entry
	lru      *list.List
	lastUsed time.Time
	matcher  *knownMatcher
	dirty    bool
}

// ID returns the caller ID.
func (c *Caller) ID() string { return c.id }

func (c *Caller) touchCaller() {
	c.mu.Lock()
	c.lastUsed = c.opts.Now()
	c.mu.Unlock()
}

func (c *Caller) lastUsedAt() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastUsed
}

// Len returns the number of stored secrets.
func (c *Caller) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.byValue)
}

// Placeholder returns the placeholder for value and remembers the mapping.
// The result depends only on the master key, the caller ID and the value
// (except after an ID collision inside this caller, which extends the ID).
func (c *Caller) Placeholder(value string) string {
	now := c.opts.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastUsed = now
	if e := c.byValue[value]; e != nil {
		e.used = now
		c.lru.MoveToFront(e.elem)
		return e.ph
	}
	m := hmac.New(sha256.New, c.key)
	m.Write([]byte(value))
	sum := hex.EncodeToString(m.Sum(nil))
	kind := Kind(value)
	var ph string
	for n := 8; n <= len(sum); n += 4 {
		ph = "<SECRET_" + kind + "_" + sum[:n] + ">"
		if e := c.byPH[ph]; e == nil || e.value == value {
			break
		}
	}
	e := &entry{value: value, ph: ph, used: now}
	e.elem = c.lru.PushFront(e)
	c.byPH[ph] = e
	c.byValue[value] = e
	c.dirty = true
	for c.lru.Len() > c.opts.MaxEntriesPerCaller {
		c.removeLocked(c.lru.Back().Value.(*entry))
	}
	return ph
}

// Restore returns the secret for a full placeholder such as
// "<SECRET_TOKEN_0123abcd>".
func (c *Caller) Restore(ph string) (string, bool) {
	now := c.opts.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.byPH[ph]
	if e == nil {
		return "", false
	}
	e.used = now
	c.lastUsed = now
	c.lru.MoveToFront(e.elem)
	return e.value, true
}

func (c *Caller) removeLocked(e *entry) {
	c.lru.Remove(e.elem)
	delete(c.byPH, e.ph)
	delete(c.byValue, e.value)
	c.dirty = true
}

func (c *Caller) sweep(now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	for el := c.lru.Back(); el != nil; {
		e := el.Value.(*entry)
		if now.Sub(e.used) <= c.opts.IdleTTL {
			break
		}
		prev := el.Prev()
		c.removeLocked(e)
		el = prev
	}
	return len(c.byValue)
}

// Range is a byte range in a scanned string.
type Range struct{ Start, End int }

// FindKnown returns non-overlapping ranges in s where a stored secret, or a
// common encoding of it (JSON-escaped, URL-encoded, base64), appears. The
// caller replaces exactly the matched bytes, so restore yields the same text.
func (c *Caller) FindKnown(s string) []Range {
	m := c.knownMatcher()
	if m == nil || len(s) < m.minLen {
		return nil
	}
	hits := m.ac.FindAllString(s)
	if len(hits) == 0 {
		return nil
	}
	slices.SortFunc(hits, func(a, b *ahocorasick.Match) int {
		if a.Index != b.Index {
			return a.Index - b.Index
		}
		return len(b.Word) - len(a.Word)
	})
	var out []Range
	end := -1
	for _, h := range hits {
		if h.Index < end {
			continue
		}
		out = append(out, Range{h.Index, h.Index + len(h.Word)})
		end = h.Index + len(h.Word)
	}
	return out
}

type knownMatcher struct {
	ac     *ahocorasick.Matcher
	minLen int
}

func (c *Caller) knownMatcher() *knownMatcher {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.dirty {
		return c.matcher
	}
	c.dirty = false
	if len(c.byValue) == 0 {
		c.matcher = nil
		return nil
	}
	seen := map[string]bool{}
	var words []string
	minLen := -1
	for v := range c.byValue {
		for _, w := range variants(v) {
			if w == "" || seen[w] {
				continue
			}
			seen[w] = true
			words = append(words, w)
			if minLen < 0 || len(w) < minLen {
				minLen = len(w)
			}
		}
	}
	slices.Sort(words)
	c.matcher = &knownMatcher{ac: ahocorasick.CompileStrings(words), minLen: minLen}
	return c.matcher
}

func variants(v string) []string {
	return []string{
		v,
		jsonEscape(v),
		url.QueryEscape(v),
		url.PathEscape(v),
		base64.StdEncoding.EncodeToString([]byte(v)),
		base64.RawStdEncoding.EncodeToString([]byte(v)),
		base64.URLEncoding.EncodeToString([]byte(v)),
		base64.RawURLEncoding.EncodeToString([]byte(v)),
	}
}

func jsonEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if c < 0x20 {
				const hexd = "0123456789abcdef"
				b.WriteString(`\u00`)
				b.WriteByte(hexd[c>>4])
				b.WriteByte(hexd[c&15])
			} else {
				b.WriteByte(c)
			}
		}
	}
	return b.String()
}
