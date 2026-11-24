// Package detector is the only package that imports betterleaks. It turns
// betterleaks findings into byte ranges inside the scanned strings.
package detector

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources"
)

//go:embed rules/proxy.toml
var builtinRules []byte

// BuiltinRules returns the embedded rule file.
func BuiltinRules() []byte { return slices.Clone(builtinRules) }

// Hit is a secret found inside one scanned string.
type Hit struct {
	RuleID string
	// Start and End are byte offsets inside the scanned string.
	Start, End int
	// Value is the secret text, s[Start:End].
	Value string
	// Encoded reports that the secret was found after decoding (base64, hex,
	// percent, unicode escapes); [Start, End) then covers the encoded form.
	Encoded bool
}

// Options configures a Detector.
type Options struct {
	// RulesFile replaces the embedded rule file when non-empty.
	RulesFile string
	// MaxDecodeDepth enables betterleaks recursive decoding.
	MaxDecodeDepth int
	// MinValueLength drops findings shorter than this many bytes.
	MinValueLength int
	// Workers bounds concurrent detection; zero uses the betterleaks default.
	Workers int
	Logger  *slog.Logger
}

// Detector finds secrets in strings. It is safe for concurrent use.
type Detector struct {
	scanner *scan.Scanner
	minLen  int
	hash    string
}

// New compiles the rule set. Compilation errors are fatal so a broken rule
// cannot silently disable detection.
func New(opts Options) (*Detector, error) {
	data := builtinRules
	name := "builtin:proxy.toml"
	if opts.RulesFile != "" {
		b, err := os.ReadFile(opts.RulesFile)
		if err != nil {
			return nil, fmt.Errorf("detector: read rules: %w", err)
		}
		data, name = b, opts.RulesFile
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	cfg, err := config.ParseTOML(data, name, config.WithLogger(logger))
	if err != nil {
		return nil, fmt.Errorf("detector: load rules: %w", err)
	}
	scanOpts := []scan.Option{
		scan.WithPrecompile(),
		scan.WithMaxDecodeDepth(opts.MaxDecodeDepth),
		scan.WithWorkers(opts.Workers),
		// Content must never be able to opt itself out of scanning.
		scan.WithAllowSignatures(),
		scan.WithLogger(logger),
	}
	s, err := scan.New(cfg, scanOpts...)
	if err != nil {
		return nil, fmt.Errorf("detector: build scanner: %w", err)
	}
	minLen := opts.MinValueLength
	if minLen <= 0 {
		minLen = 8
	}
	return &Detector{scanner: s, minLen: minLen, hash: cfg.Hash()}, nil
}

// RulesHash identifies the compiled rule set.
func (d *Detector) RulesHash() string { return d.hash }

const attrIndex = "keycordon.index"

type textsSource []string

func (t textsSource) Fragments(ctx context.Context, yield sources.FragmentsFunc) error {
	for i, s := range t {
		if s == "" {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		f := sources.Fragment{Raw: s, Attributes: map[string]string{attrIndex: strconv.Itoa(i)}}
		if err := yield(f, nil); err != nil {
			return err
		}
	}
	return nil
}

// Scan scans every text and returns the hits per text, sorted and merged so
// they never overlap. An error means the scan did not complete; callers must
// treat the input as unscanned.
func (d *Detector) Scan(ctx context.Context, texts []string) ([][]Hit, error) {
	out := make([][]Hit, len(texts))
	if len(texts) == 0 {
		return out, nil
	}
	_, err := d.scanner.Scan(ctx, textsSource(texts), func(f report.Finding) error {
		i, err := strconv.Atoi(f.Attributes[attrIndex])
		if err != nil || i < 0 || i >= len(texts) {
			return errors.New("detector: finding without source index")
		}
		out[i] = append(out[i], locate(texts[i], f, d.minLen)...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	for i := range out {
		// CJK labels are matched here, not by a betterleaks rule: a rule
		// cannot be keyword-gated on multi-byte text (see cjk.go).
		out[i] = mergeCJK(texts[i], out[i], cjkHits(texts[i], d.minLen))
	}
	return out, nil
}

// ScanOne scans a single string.
func (d *Detector) ScanOne(ctx context.Context, s string) ([]Hit, error) {
	r, err := d.Scan(ctx, []string{s})
	if err != nil {
		return nil, err
	}
	return r[0], nil
}

// locate converts a finding into byte ranges in s.
func locate(s string, f report.Finding, minLen int) []Hit {
	start, end, ok := locationRange(s, f.Location)
	if !ok {
		return locateEverywhere(s, f, minLen)
	}
	if len(f.Encodings) > 0 {
		a, b := widenEncoded(s, start, end)
		if b-a < minLen {
			return nil
		}
		return []Hit{{RuleID: f.RuleID, Start: a, End: b, Value: s[a:b], Encoded: true}}
	}
	v := f.Match.Value
	if len(v) < minLen {
		return nil
	}
	if i := strings.Index(s[start:end], v); i >= 0 {
		return []Hit{{RuleID: f.RuleID, Start: start + i, End: start + i + len(v), Value: v}}
	}
	return locateEverywhere(s, f, minLen)
}

// locateEverywhere is the fallback when the reported location does not
// contain the value: every occurrence of the value is treated as secret.
func locateEverywhere(s string, f report.Finding, minLen int) []Hit {
	v := f.Match.Value
	if len(v) < minLen {
		return nil
	}
	var hits []Hit
	for off := 0; ; {
		i := strings.Index(s[off:], v)
		if i < 0 {
			return hits
		}
		hits = append(hits, Hit{RuleID: f.RuleID, Start: off + i, End: off + i + len(v), Value: v})
		off += i + len(v)
	}
}

// locationRange maps a betterleaks location (1-based line, 1-based start
// column, inclusive end column, all in bytes) to [start, end).
func locationRange(s string, loc report.Location) (int, int, bool) {
	if loc.StartLine <= 0 || loc.EndLine < loc.StartLine {
		return 0, 0, false
	}
	starts := lineStarts(s)
	if loc.EndLine > len(starts) {
		return 0, 0, false
	}
	a := starts[loc.StartLine-1] + loc.StartColumn - 1
	b := starts[loc.EndLine-1] + loc.EndColumn
	if a < 0 || b > len(s) || a > b {
		return 0, 0, false
	}
	return a, b, true
}

func lineStarts(s string) []int {
	starts := []int{0}
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' && i+1 < len(s) {
			starts = append(starts, i+1)
		}
	}
	return starts
}

func isEncodedChar(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
		c == '+' || c == '/' || c == '=' || c == '-' || c == '_' || c == '%' || c == '\\'
}

// widenEncoded expands [a, b) to the surrounding run of encoding characters
// so the whole encoded blob is replaced, not a fragment of it.
func widenEncoded(s string, a, b int) (int, int) {
	for a < b && !isEncodedChar(s[a]) {
		a++
	}
	for b > a && !isEncodedChar(s[b-1]) {
		b--
	}
	for a > 0 && isEncodedChar(s[a-1]) {
		a--
	}
	for b < len(s) && isEncodedChar(s[b]) {
		b++
	}
	return a, b
}

// dropShadowedBare removes bare-random-token hits that overlap a hit of a
// rule with real context when the extra bytes of the bare hit start at a
// URL/URI delimiter. The context rule knows the secret's extent, while the
// bare token's wide charset tends to swallow neighbours such as "@host/db"
// of a connection string. In every other case the union is kept.
func dropShadowedBare(s string, hits []Hit) []Hit {
	out := hits[:0:0]
	for _, h := range hits {
		if h.RuleID == bareRule && !h.Encoded && shadowed(s, h, hits) {
			continue
		}
		out = append(out, h)
	}
	return out
}

func shadowed(s string, h Hit, hits []Hit) bool {
	for _, o := range hits {
		if o.RuleID == bareRule || o.End <= h.Start || h.End <= o.Start {
			continue
		}
		left := h.Start >= o.Start || strings.IndexByte(":/@=", s[o.Start-1]) >= 0
		right := h.End <= o.End || strings.IndexByte("@/:?#&", s[o.End]) >= 0
		if left && right {
			return true
		}
	}
	return false
}

const bareRule = "bare-random-token"

// genericRule reports rules whose ID says little about the secret type; a
// specific rule ID wins when ranges are merged.
func genericRule(id string) bool {
	return id == "bare-random-token" || id == "compound-env-secret" || strings.HasPrefix(id, "generic")
}

// Merge sorts hits and unions overlapping ranges. The merged value is taken
// from s; a specific rule ID is preferred over a generic one.
func Merge(s string, hits []Hit) []Hit {
	if len(hits) < 2 {
		return hits
	}
	hits = dropShadowedBare(s, hits)
	slices.SortFunc(hits, func(a, b Hit) int {
		if a.Start != b.Start {
			return a.Start - b.Start
		}
		return b.End - a.End
	})
	out := hits[:1]
	for _, h := range hits[1:] {
		last := &out[len(out)-1]
		if h.Start < last.End {
			if h.End > last.End {
				last.End = h.End
				last.Value = s[last.Start:last.End]
			}
			last.Encoded = last.Encoded || h.Encoded
			if genericRule(last.RuleID) && !genericRule(h.RuleID) {
				last.RuleID = h.RuleID
			}
			continue
		}
		out = append(out, h)
	}
	return out
}
