package rewrite

import "strings"

// A single string can be enormous: a pasted file, a tool result holding a
// diff, a base64 blob. betterleaks scans one unit per worker slot, so a text
// that large is handled by one core while the rest idle. Measured on a 4-core
// box, a 64 KiB unit runs at 1.6 MB/s and the same bytes in four pieces at
// 5.6 MB/s.
//
// Splitting is not free: a secret that straddles a cut is invisible to both
// halves, and a context rule needs the words before the value. The cut
// therefore overlaps. With chunk size C and overlap O, the stride is S = C-O
// and the chunk holding position p starts at floor(p/S)*S, which is at most p
// and at least p-S+1. That chunk also extends to floor(p/S)*S+C >= p+O, so
// every position is seen with at least O bytes of context on both sides.
// Any secret shorter than O, and any context window narrower than O, is still
// matched in full.
//
// O is 8 KiB, an order of magnitude more than the longest realistic secret: a
// 4096-bit PEM key is about 3.3 KiB. The scan reads C/S = 64/56, so 14% more
// bytes in exchange for four times as many units to spread over the cores.
const (
	// chunkMinSize is where splitting starts to pay. Below it there are too
	// few pieces for the extra copies to be worth the parallelism.
	chunkMinSize = 256 << 10
	chunkSize    = 64 << 10
	chunkOverlap = 8 << 10
)

// splitText returns the slices of an n-byte text to scan instead of the whole
// text, or nil when one pass is right. Overlapping slices mean a secret
// crossing a cut is still seen whole by the slice that holds it.
func splitText(n int) []chunkRange {
	if n < chunkMinSize {
		return nil
	}
	stride := chunkSize - chunkOverlap
	out := make([]chunkRange, 0, n/stride+1)
	for start := 0; start < n; start += stride {
		end := min(start+chunkSize, n)
		out = append(out, chunkRange{start, end})
		if end == n {
			break
		}
	}
	return out
}

// chunkRange is one slice of a unit's text, as offsets into that text.
type chunkRange struct{ start, end int }

// plan decides how one unit goes to the detector: whole, or as overlapping
// slices.
//
// Chunking is safe only when every secret the rules can match is shorter than
// the overlap. Most are, but private-key-style rules match an arbitrarily long
// block, and a 30000-byte key straddling a cut was measured to be missed
// entirely. When the text carries such a match, the unit is scanned whole: one
// core scanning it is much better than a silent miss.
func (rw *Rewriter) plan(u *unit) ([]chunkRange, bool) {
	parts := splitText(len(u.text))
	if parts == nil {
		return nil, false
	}
	if hasOversizedBlock(u.text) {
		return nil, false
	}
	return parts, true
}

// blockMarkers are the beginnings of block-structured secrets whose length is
// not bounded by any of the rule sets' quantifiers. Their presence is cheap to
// check and conservative: a text that mentions one is scanned as a whole even
// if the block turns out to be short.
var blockMarkers = []string{"-----BEGIN", "AKIA", "ssh-rsa AAAA", "ssh-ed25519 AAAA"}

func hasOversizedBlock(s string) bool {
	for _, m := range blockMarkers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}
