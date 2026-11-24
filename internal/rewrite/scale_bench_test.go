package rewrite

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"gitlab.soraharu.com/XiaoXi/keycordon/internal/vault"
)

// Scale benchmarks: what does keycordon cost on a real agent request?
//
// A "token" here is four bytes of English prose, which is what cl100k and its
// successors average. Sizes run to 1M tokens, the largest context the current
// models accept.
//
// Run all of them:
//   go test ./internal/rewrite -run xxx -bench Scale -benchtime 3x -timeout 30m
//
// Run one size:
//   go test ./internal/rewrite -run xxx -bench 'Scale1M' -benchtime 3x -timeout 30m

// prose is a paragraph of ordinary text: no secrets, nothing a rule matches.
const prose = "The deployment runs under systemd and writes its logs to the journal. " +
	"Configuration lives under /etc/svc and is reloaded with SIGHUP. " +
	"Health checks poll the readiness endpoint every ten seconds. "

// secret returns the i-th made-up credential. Every one is a distinct value,
// so the vault grows with the key count as it does in production.
func secret(i int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 28)
	for j := range b {
		b[j] = alphabet[(i*7+j*11)%len(alphabet)]
	}
	return fmt.Sprintf("ghp_%s%02d", b, i%100)
}

// chatBody builds a chat request of about tokens tokens with keys distinct
// secrets spread through it, the way an agent's history carries the .env it
// read: each secret sits in a line of its own, as `KEY=value`.
func chatBody(tokens, keys int) []byte {
	const perMsg = 2000 // about 500 tokens per message
	var sb strings.Builder
	sb.WriteString(`{"model":"gpt-5","stream":true,"messages":[{"role":"system","content":"`)
	sb.WriteString(strings.Repeat(prose, 4))
	sb.WriteString(`"}`)

	remaining := max(tokens*4-sb.Len(), perMsg*2)
	n := remaining / perMsg
	// Spread the keys over the messages that have room for them, one per
	// message at most when there are few, several when there are many.
	perKey := 1
	if keys > n {
		perKey = (keys + n - 1) / n
		nKeys := (keys + perKey - 1) / perKey
		n = max(n, nKeys)
	}
	placed, written := 0, 0
	for i := 0; written < remaining || placed < keys; i++ {
		sb.WriteString(`,{"role":"`)
		if i%2 == 0 {
			sb.WriteString("user")
		} else {
			sb.WriteString("assistant")
		}
		sb.WriteString(`","content":"`)
		var text strings.Builder
		if placed < keys && i >= 1 && i%2 == 1 {
			for k := 0; k < perKey && placed < keys; k++ {
				fmt.Fprintf(&text, "GITHUB_TOKEN=%s\\n", secret(placed))
				placed++
			}
		}
		for text.Len() < perMsg && written < remaining {
			text.WriteString(prose)
			written += len(prose)
		}
		sb.WriteString(text.String())
		sb.WriteString(`"}`)
		written += 40
	}
	sb.WriteString(`]}`)
	return []byte(sb.String())
}

func benchRewrite(b *testing.B, tokens, keys int) {
	setup(b)
	a := adapter(b, "/v1/chat/completions")
	body := chatBody(tokens, keys)
	// A fresh caller per iteration would hide the vault lookup; one caller
	// with everything already known is the steady state of a long session.
	c := vault.New([]byte(master32), vault.Options{}).Caller("local")
	rw := newRW(true)
	ctx := context.Background()

	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res, err := rw.JSON(ctx, a, body, c)
		if err != nil {
			b.Fatal(err)
		}
		if keys > 0 && res.Count() == 0 {
			b.Fatal("no key replaced")
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(len(body))/1024, "KiB/req")
}

// Sizes: 4K, 16K, 64K, 256K, 1M tokens. 0 / 10 / 100 / 1000 keys.
func BenchmarkScale4K0(b *testing.B)    { benchRewrite(b, 4000, 0) }
func BenchmarkScale4K10(b *testing.B)   { benchRewrite(b, 4000, 10) }
func BenchmarkScale4K100(b *testing.B)  { benchRewrite(b, 4000, 100) }
func BenchmarkScale16K0(b *testing.B)   { benchRewrite(b, 16000, 0) }
func BenchmarkScale16K10(b *testing.B)  { benchRewrite(b, 16000, 10) }
func BenchmarkScale16K100(b *testing.B) { benchRewrite(b, 16000, 100) }
func BenchmarkScale64K0(b *testing.B)   { benchRewrite(b, 64000, 0) }
func BenchmarkScale64K10(b *testing.B)  { benchRewrite(b, 64000, 10) }
func BenchmarkScale64K100(b *testing.B) { benchRewrite(b, 64000, 100) }
func BenchmarkScale256K0(b *testing.B)  { benchRewrite(b, 256000, 0) }
func BenchmarkScale256K100(b *testing.B) {
	benchRewrite(b, 256000, 100)
}
func BenchmarkScale256K1000(b *testing.B) {
	benchRewrite(b, 256000, 1000)
}
func BenchmarkScale1M0(b *testing.B)    { benchRewrite(b, 1000000, 0) }
func BenchmarkScale1M100(b *testing.B)  { benchRewrite(b, 1000000, 100) }
func BenchmarkScale1M1000(b *testing.B) { benchRewrite(b, 1000000, 1000) }

// TestScaleShapes guards the generator: every size produces a valid request
// with the requested number of distinct secrets.
func TestScaleShapes(t *testing.T) {
	for _, c := range []struct{ tokens, keys int }{
		{4000, 0}, {4000, 10}, {16000, 100}, {64000, 100},
	} {
		body := chatBody(c.tokens, c.keys)
		var v struct {
			Messages []struct{ Content string } `json:"messages"`
		}
		if err := json.Unmarshal(body, &v); err != nil {
			t.Fatalf("%d/%d: %v", c.tokens, c.keys, err)
		}
		got := strings.Count(string(body), "GITHUB_TOKEN=")
		if got != c.keys {
			t.Errorf("%d tokens %d keys: placed %d", c.tokens, c.keys, got)
		}
		t.Logf("%6d tokens %4d keys: %8.1f KiB, %4d messages",
			c.tokens, c.keys, float64(len(body))/1024, len(v.Messages))
	}
}
