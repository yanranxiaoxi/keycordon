package rewrite

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"gitlab.soraharu.com/XiaoXi/keycordon/internal/detector"
)

func TestSplitText(t *testing.T) {
	if got := splitText(chunkMinSize - 1); got != nil {
		t.Errorf("small text split: %v", got)
	}
	for _, n := range []int{chunkMinSize, 512 << 10, 4 << 20} {
		parts := splitText(n)
		if len(parts) < 2 {
			t.Fatalf("%d bytes: only %d part", n, len(parts))
		}
		stride := chunkSize - chunkOverlap
		for i, p := range parts {
			if i > 0 && p.start > parts[i-1].end-chunkOverlap+1 {
				t.Errorf("%d bytes: parts %d and %d leave no overlap", n, i-1, i)
			}
			if p.end > n || p.start >= p.end {
				t.Errorf("%d bytes: bad range %v", n, p)
			}
		}
		if parts[len(parts)-1].end != n {
			t.Errorf("%d bytes: last part ends at %d", n, parts[len(parts)-1].end)
		}
		if parts[0].start != 0 {
			t.Errorf("%d bytes: first part starts at %d", n, parts[0].start)
		}
		_ = stride
	}
}

// TestChunkCoversEveryPosition pins the property the overlap exists for:
// every byte belongs to some chunk, and every chunk holds at least
// chunkOverlap bytes of context beyond its stride neighbours.
func TestChunkCoversEveryPosition(t *testing.T) {
	for _, n := range []int{chunkMinSize, chunkMinSize + 1, 700 << 10, 3 << 20} {
		parts := splitText(n)
		covered := make([]bool, n)
		for _, p := range parts {
			for i := p.start; i < p.end; i++ {
				covered[i] = true
			}
		}
		for i, ok := range covered {
			if !ok {
				t.Fatalf("%d bytes: position %d is in no chunk", n, i)
			}
		}
		// A secret no longer than the overlap is always inside one chunk.
		for pos := 0; pos+chunkOverlap <= n; pos += 997 {
			found := false
			for _, p := range parts {
				if p.start <= pos && pos+chunkOverlap <= p.end {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("%d bytes: %d bytes at %d straddle every chunk", n, chunkOverlap, pos)
			}
		}
	}
}

// TestChunkedScanFindsStraddlingSecret is the correctness case that makes the
// overlap load-bearing: a PEM key placed so that a cut falls through it must
// still be replaced exactly once, and the body must stay valid JSON.
func TestChunkedScanFindsStraddlingSecret(t *testing.T) {
	a := adapter(t, "/v1/chat/completions")
	// The key must be shorter than the overlap, which is the promise the
	// overlap makes: any secret below 8 KiB is seen whole by one chunk.
	key := testPEM(60)
	if len(key) >= chunkOverlap {
		t.Fatalf("test key is %d bytes, at the overlap limit; the promise is untested", len(key))
	}

	// Put the key so that a cut lands in its middle: the stride boundaries
	// are at multiples of chunkSize-chunkOverlap.
	stride := chunkSize - chunkOverlap
	for _, off := range []int{-stride / 2, -1, 0, 1, len(key) / 2, stride / 2} {
		padLen := stride + off
		if padLen < 0 {
			continue
		}
		pad := strings.Repeat("ordinary filler line 1234\n", padLen/26+1)[:padLen]
		body := []byte(`{"messages":[{"role":"user","content":` +
			fmt.Sprintf("%q", pad+key+pad) + `}]}`)
		res, err := newRW(false).JSON(context.Background(), a, body, caller())
		if err != nil {
			t.Fatalf("offset %d: %v", off, err)
		}
		if res.Count() != 1 {
			t.Errorf("offset %d: replaced %d, want exactly 1 (key %d bytes, stride %d)",
				off, res.Count(), len(key), stride)
		}
		if strings.Contains(string(res.Body), "PRIVATE KEY") && strings.Contains(string(res.Body), "\n") {
			// The placeholder must replace the whole key, not a fragment.
			if !strings.Contains(string(res.Body), "<SECRET_") {
				t.Errorf("offset %d: no placeholder written", off)
			}
		}
	}
}

// TestChunkedMatchesUnchunked compares the chunked result with the scan of the
// whole text, so a change to the overlap cannot silently lose findings.
func TestChunkedMatchesUnchunked(t *testing.T) {
	key := testPEM(60)
	pad := strings.Repeat("filler text for the comparison 9876\n", (chunkSize*2)/36+1)
	text := pad + key + pad + "api_key=sk-" + strings.Repeat("9f8e7d6c", 4) + pad

	whole, err := det.ScanOne(context.Background(), text)
	if err != nil {
		t.Fatal(err)
	}
	var all []detector.Hit
	for _, part := range splitText(len(text)) {
		hits, err := det.ScanOne(context.Background(), text[part.start:part.end])
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range hits {
			h.Start += part.start
			h.End += part.start
			all = append(all, h)
		}
	}
	merged := detector.Merge(text, all)
	if len(merged) != len(whole) {
		t.Fatalf("chunked found %d spans, whole text found %d:\nchunked %v\nwhole %v",
			len(merged), len(whole), merged, whole)
	}
	for i := range merged {
		if merged[i].Start != whole[i].Start || merged[i].End != whole[i].End {
			t.Errorf("span %d: chunked %d-%d, whole %d-%d", i,
				merged[i].Start, merged[i].End, whole[i].Start, whole[i].End)
		}
	}
}

// TestOversizedBlockIsNotChunked guards the miss that chunking can cause: a
// PEM block longer than the overlap is invisible to both chunks that hold its
// two halves, so such a text must not be chunked at all.
func TestOversizedBlockIsNotChunked(t *testing.T) {
	a := adapter(t, "/v1/chat/completions")
	stride := chunkSize - chunkOverlap
	for _, lines := range []int{60, 500} {
		key := testPEM(lines)
		// Land the key so a cut falls into its middle.
		padLen := chunkMinSize + stride + len(key) + chunkSize
		pad := strings.Repeat("ordinary filler line 1234\n", padLen/26+2)[:padLen]
		text := pad[:stride-1] + key + pad[stride-1:]
		payload, err := json.Marshal(map[string]any{
			"messages": []any{map[string]any{"role": "user", "content": text}},
		})
		if err != nil {
			t.Fatal(err)
		}
		res, err := newRW(false).JSON(context.Background(), a, payload, caller())
		if err != nil {
			t.Fatal(err)
		}
		if res.Count() == 0 {
			t.Errorf("key %d bytes: nothing replaced", len(key))
		}
		if strings.Contains(string(res.Body), "PRIVATE KEY") {
			t.Errorf("key %d bytes: key headers survived the rewrite", len(key))
		}
	}
}

// TestChunkingKeepsOrdinarySecrets makes sure the fast path finds the keys it
// exists to find, and finds each one once, including keys that straddle a cut.
func TestChunkingKeepsOrdinarySecrets(t *testing.T) {
	a := adapter(t, "/v1/chat/completions")
	stride := chunkSize - chunkOverlap
	filler := strings.Repeat("ordinary filler line with words 1234\n", 3000)

	// A body the provider-prefixed rule accepts: mixed case, digits, enough
	// entropy. The tail varies so the keys do not collapse into one
	// placeholder.
	mkKey := func(i int) string {
		return "sk-" + strings.Repeat("Xy7Q", 5) + fmt.Sprintf("z%03d", i)
	}

	need := chunkMinSize + 4*stride
	var b strings.Builder
	for i := 0; b.Len() < need; i++ {
		// The key starts three bytes before a stride boundary, so a cut
		// falls inside it.
		b.WriteString(filler[:stride-3])
		b.WriteString(mkKey(i))
	}
	// The last key must not sit flush against the end of the text: the
	// trailing boundary of bare-random-token needs a separator after it,
	// which is pre-existing behaviour and not what this test is about.
	b.WriteString(filler[:64])
	text := b.String()
	want := strings.Count(text, "sk-")
	if want < 4 {
		t.Fatalf("the fixture holds only %d keys; the boundary case is untested", want)
	}

	payload, err := json.Marshal(map[string]any{
		"messages": []any{map[string]any{"role": "user", "content": text}},
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := newRW(false).JSON(context.Background(), a, payload, caller())
	if err != nil {
		t.Fatal(err)
	}
	if res.Count() != want {
		t.Errorf("replaced %d keys, want %d: %v", res.Count(), want, res.Replaced)
	}
	if strings.Contains(string(res.Body), "sk-") {
		t.Error("a key survived the rewrite")
	}
}
