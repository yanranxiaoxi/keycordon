package detector

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"gitlab.soraharu.com/XiaoXi/keycordon/internal/veto"
)

// evalCase is one text an agent sends, with the values that must be masked
// and those that must go as written.
type evalCase struct {
	ID   string   `json:"id"`
	Text string   `json:"text"`
	Want []string `json:"want"`
	Keep []string `json:"keep"`
}

// Thresholds are the CI gate. A change that trades recall for precision
// (or the reverse) has to say so here.
const (
	minPrecision = 0.95
	minRecall    = 0.95
)

// TestEvalCorpus scores the detector on the evaluation corpus. It is the
// regression gate for the rules: every case is a text an agent sends, and
// the values in it are either secrets (want) or ordinary text (keep).
func TestEvalCorpus(t *testing.T) {
	data, err := os.ReadFile("testdata/eval.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []evalCase `json:"cases"`
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Cases) < 30 {
		t.Fatalf("corpus has only %d cases", len(corpus.Cases))
	}
	d := det(t)
	var tp, fp, fn int
	for _, c := range corpus.Cases {
		hits, err := d.ScanOne(context.Background(), c.Text)
		if err != nil {
			t.Fatalf("%s: %v", c.ID, err)
		}
		// The corpus scores the whole decision, not just the rules: a
		// finding the rewrite layer vetoes (code, paths, versions) goes as
		// written, so it is not masked.
		masked := make([]string, 0, len(hits))
		for _, h := range hits {
			if veto.Reject(c.Text, h.Start, h.End) {
				continue
			}
			masked = append(masked, h.Value)
		}
		for _, want := range c.Want {
			if contains(masked, want) {
				tp++
			} else {
				fn++
				t.Errorf("%s: missed %q (masked %q)", c.ID, want, masked)
			}
		}
		for _, keep := range c.Keep {
			if contains(masked, keep) {
				fp++
				t.Errorf("%s: masked %q, which is not a secret", c.ID, keep)
			}
		}
	}
	precision, recall := 1.0, 1.0
	if tp+fp > 0 {
		precision = float64(tp) / float64(tp+fp)
	}
	if tp+fn > 0 {
		recall = float64(tp) / float64(tp+fn)
	}
	t.Logf("precision %.3f recall %.3f (tp=%d fp=%d fn=%d)", precision, recall, tp, fp, fn)
	if precision < minPrecision {
		t.Errorf("precision %.3f below %.2f", precision, minPrecision)
	}
	if recall < minRecall {
		t.Errorf("recall %.3f below %.2f", recall, minRecall)
	}
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
