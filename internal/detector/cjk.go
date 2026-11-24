package detector

import (
	"regexp"
	"slices"
	"strings"

	"github.com/rrethy/ahocorasick"
)

// CJK credentials: 密码、口令、密钥… are found here rather than as a
// betterleaks rule.
//
// A rule whose regex alternation starts with many multi-byte literals makes
// Go's regexp run its NFA at every byte offset: with 35 CJK labels it cost
// 20 ms per 100 KB, 170x the whole rest of the scan (3.9 MB/s against
// 717 MB/s with the rule removed). betterleaks only skips a rule when one of
// its keywords occurs, and a keyword must be an ASCII lowercase literal that
// occurs in the text — a CJK keyword never matches, so the rule could not be
// gated, and a no-keyword rule is tried on every fragment.
//
// An Aho-Corasick pass over the same labels costs 0.2 MB/µs (447 MB/s on
// ASCII, 213 MB/s on CJK) and yields the exact offsets, so the regex only
// runs on the bytes right after a label — a window of a few hundred bytes.
// The rules and filters below are the same as the TOML rule this replaces,
// so behaviour does not change (see TestCJKLedger).

// cjkLabels are what a password, key or token is called in Chinese, Japanese
// and Korean, in the forms agents see them.
var cjkLabels = []string{
	"密码", "密碼", "口令", "密钥", "密鑰", "秘钥", "秘鑰", "私钥", "私鑰",
	"金钥", "金鑰", "令牌", "权杖", "權杖", "凭证", "憑證", "票据", "票據",
	"授权码", "授權碼", "安全码", "安全碼", "PIN码", "PIN碼",
	"パスワード", "暗証番号", "シークレット", "トークン",
	"APIキー", "アクセスキー",
	"비밀번호", "암호", "비번", "토큰", "비밀키",
}

var (
	cjkMatcher = ahocorasick.CompileStrings(cjkLabels)

	// cjkTail is what may follow a label: a separator (ASCII or CJK) and an
	// optional quote, then the value. Anchored, and only ever run on the
	// bytes after a label.
	cjkTail = regexp.MustCompile("^(?:(?:=>|:=|[:=：＝]|是|為|为|＝|は)[ \t]{0,2}|[ \t]+)" +
		"[\"`]?([^\\s\"`,;，。、]{4,256})[\"`]?")

	// cjkReject drops candidates that are prose or a placeholder.
	cjkReject = []*regexp.Regexp{
		// Templates and existing placeholders.
		regexp.MustCompile(`^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$`),
		regexp.MustCompile(`^\{\{.*\}\}$`),
		regexp.MustCompile(`^<[^>]+>$`),
		// Schema words: "密码是 password 字段" describes a field.
		regexp.MustCompile(`^(?i:true|false|null|none|required|optional|changeme|placeholder|hidden|removed|unset|empty|unknown|redacted|masked|default|invalid|expired|missing|wrong|correct|incorrect|valid|readonly|read-only|disabled|enabled|string|number|boolean|object|array|integer|nobody|anyone|same|different|public|private|test|testing|production|staging|local|remote|here|there|this|that)$`),
		regexp.MustCompile(`^\d+$`),
		regexp.MustCompile(`^[^@\s]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$`),
		regexp.MustCompile(`^(?i:password|passwd|passphrase|token|secret|apikey|api|key|credential|auth|login|user|username|host|port|database|db|table|column|schema)$`),
	}
)

// cjkHits finds credentials announced after a CJK label.
//
// A CJK label is followed by real prose far more often than by a secret, so
// the candidate must be printable ASCII (which rejects "必需的字段"), at least
// four bytes, and not a schema word. Unlike the English rule, a value of
// letters only is taken: nothing in code is called 密码, so the
// false-positive rate is low and a password of words is still a password.
func cjkHits(s string, minLen int) []Hit {
	if !hasNonASCII(s) {
		return nil
	}
	var out []Hit
	for _, m := range cjkMatcher.FindAllString(s) {
		start := m.Index + len(m.Word)
		if start >= len(s) {
			continue
		}
		window := s[start:min(start+320, len(s))]
		sub := cjkTail.FindStringSubmatch(window)
		if sub == nil {
			continue
		}
		value := sub[1]
		// The value starts after the whole match minus the value itself,
		// including the quote the pattern allowed.
		a := start + strings.LastIndex(window[:len(sub[0])], value)
		b := a + len(value)
		if b > len(s) || a >= b {
			continue
		}
		if b-a < max(minLen, 4) || strings.TrimSpace(value) != value {
			continue
		}
		if !printableASCII(value) || cjkRejected(value) {
			continue
		}
		out = append(out, Hit{RuleID: "nl-credential-mention-cjk", Start: a, End: b, Value: value})
	}
	return out
}

func cjkRejected(v string) bool {
	for _, re := range cjkReject {
		if re.MatchString(v) {
			return true
		}
	}
	return false
}

// hasNonASCII is a cheap gate: a text of ASCII only cannot hold a CJK label.
func hasNonASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return true
		}
	}
	return false
}

// printableASCII reports a value of printable ASCII only: no CJK, no spaces,
// no control characters.
func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// mergeCJK folds the native findings into a text's hits, keeping one hit per
// value and dropping any that a betterleaks rule already covers.
func mergeCJK(s string, hits []Hit, extra []Hit) []Hit {
	if len(extra) > 0 {
		hits = appendMissing(hits, extra)
	}
	// Merge also drops a bare-token hit that a context rule shadows, which
	// matters: a CJK hit is a context hit like any other.
	return Merge(s, hits)
}

// appendMissing adds the findings a text does not already have covered.
func appendMissing(hits, extra []Hit) []Hit {
	for _, e := range extra {
		covered := slices.ContainsFunc(hits, func(h Hit) bool {
			return h.Start < e.End && e.Start < h.End
		})
		if !covered {
			hits = append(hits, e)
		}
	}
	return hits
}
