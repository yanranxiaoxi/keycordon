package rewrite

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"gitlab.soraharu.com/XiaoXi/keycordon/internal/vault"
)

// TestScaleTable prints what a request costs at every context size and key
// count. It is a report, not an assertion: run it to see the numbers.
//
//	go test ./internal/rewrite -run TestScaleTable -v -timeout 20m
//
// "cold" is a first request: nothing in the vault, nothing in the sent memo.
// "warm" is the same request again, which is what a second turn of a
// conversation looks like after the first turn's secrets are known.
// "memo" is the same request a third time, with every span frozen by the
// sent memo (design 7.8), which is what a long agent session converges to.
func TestScaleTable(t *testing.T) {
	if testing.Short() {
		t.Skip("scale table skipped in -short")
	}
	if os.Getenv("SCALE") == "" {
		t.Skip("set SCALE=1 to print the table (it takes about 8 s)")
	}
	setup(t)
	a := adapter(t, "/v1/chat/completions")
	ctx := context.Background()

	sizes := []int{4000, 16000, 64000, 256000, 1000000}
	keyCounts := []int{0, 10, 100, 1000}
	const reps = 5

	out := os.Getenv("SCALE_OUT")
	line := func(format string, args ...any) {
		fmt.Printf(format+"\n", args...)
		if out != "" {
			f, err := os.OpenFile(out, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
			if err == nil {
				fmt.Fprintf(f, format+"\n", args...)
				f.Close()
			}
		}
	}

	line("%7s %6s %10s %10s %10s %9s %9s", "tokens", "keys", "bytes", "cold ms", "warm ms", "memo ms", "MB/s")
	for _, tokens := range sizes {
		for _, keys := range keyCounts {
			if keys == 1000 && tokens < 64000 {
				continue // 1000 keys need room to be spread over
			}
			body := chatBody(tokens, keys)
			// cold: a fresh caller, measured over one call only
			cold := func() float64 {
				c := vault.New([]byte(master32), vault.Options{}).Caller("local")
				rw := newRW(true)
				var total time.Duration
				for i := 0; i < reps; i++ {
					c = vault.New([]byte(master32), vault.Options{}).Caller("local")
					start := time.Now()
					if _, err := rw.JSON(ctx, a, body, c); err != nil {
						t.Fatal(err)
					}
					total += time.Since(start)
				}
				return float64(total.Microseconds()) / 1000 / reps
			}()
			// warm: one caller, the first call primes it
			c := vault.New([]byte(master32), vault.Options{}).Caller("local")
			rw := newRW(true)
			if _, err := rw.JSON(ctx, a, body, c); err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			for i := 0; i < reps; i++ {
				if _, err := rw.JSON(ctx, a, body, c); err != nil {
					t.Fatal(err)
				}
			}
			warm := float64(time.Since(start).Microseconds()) / 1000 / reps
			// memo: a second caller with the same body, so every unit is in
			// the sent memo but the vault is cold — the steady state of a
			// long session where the same history is re-sent.
			c2 := vault.New([]byte(master32), vault.Options{}).Caller("local")
			if _, err := rw.JSON(ctx, a, body, c2); err != nil {
				t.Fatal(err)
			}
			start = time.Now()
			for i := 0; i < reps; i++ {
				if _, err := rw.JSON(ctx, a, body, c2); err != nil {
					t.Fatal(err)
				}
			}
			memo := float64(time.Since(start).Microseconds()) / 1000 / reps
			best := min(cold, warm, memo)
			line("%7d %6d %9.1fK %10.2f %10.2f %10.2f %9.1f",
				tokens, keys, float64(len(body))/1024, cold, warm, memo,
				float64(len(body))/1024/1024/(best/1000))
		}
	}
}
