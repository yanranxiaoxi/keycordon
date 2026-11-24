package detector

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/scan"
)

var testDet *Detector

func det(t testing.TB) *Detector {
	t.Helper()
	if testDet == nil {
		d, err := New(Options{MaxDecodeDepth: 2})
		if err != nil {
			t.Fatal(err)
		}
		testDet = d
	}
	return testDet
}

// TestEmbeddedRuleTests runs the [[rules.tests]] cases of keycordon's own rules.
func TestEmbeddedRuleTests(t *testing.T) {
	cfg, err := config.ParseTOML(builtinRules, "proxy.toml")
	if err != nil {
		t.Fatal(err)
	}
	own := map[string]bool{}
	for _, id := range []string{"compound-env-secret", "db-uri-anon-user", "openai-project-key", "yaml-netrc-secret", "nl-credential-mention", "bare-random-token"} {
		own[id] = true
	}
	n := 0
	for _, r := range cfg.Rules {
		if !own[r.ID] {
			continue
		}
		single := *cfg
		single.Rules = []config.Rule{r}
		s, err := scan.New(&single, scan.WithAllowSignatures())
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range r.Tests {
			n++
			var got []string
			for _, f := range s.ScanString(tc.Input) {
				if f.RuleID == r.ID {
					got = append(got, f.Match.Value)
				}
			}
			var want []string
			for _, e := range tc.Expect {
				want = append(want, e.Secret)
			}
			if strings.Join(got, "|") != strings.Join(want, "|") {
				t.Errorf("%s / %s: got %q want %q", r.ID, tc.Name, got, want)
			}
		}
	}
	if n < 20 {
		t.Fatalf("only %d rule tests ran", n)
	}
}

func TestScanOffsets(t *testing.T) {
	d := det(t)
	key := "ghp_NqVwYS81VP7Hb1DX8pQ2mZ7xL4kR9tWcB3vE"
	texts := []string{
		"line1\nmy token is " + key + " ok",
		"中文前缀 " + key,
		"nothing here",
		"",
	}
	res, err := d.Scan(context.Background(), texts)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []int{1, 1, 0, 0} {
		if len(res[i]) != want {
			t.Fatalf("text %d: %d hits %+v", i, len(res[i]), res[i])
		}
		for _, h := range res[i] {
			if texts[i][h.Start:h.End] != key || h.Value != key {
				t.Fatalf("text %d: bad range %+v", i, h)
			}
		}
	}
}

func TestScanEncoded(t *testing.T) {
	d := det(t)
	key := "ghp_NqVwYS81VP7Hb1DX8pQ2mZ7xL4kR9tWcB3vE"
	enc := base64.StdEncoding.EncodeToString([]byte("GITHUB_TOKEN=" + key))
	s := "blob: " + enc + " end"
	hits, err := d.ScanOne(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Value != enc || !hits[0].Encoded {
		t.Fatalf("hits = %+v", hits)
	}
}

func TestAllowSignatureDisabled(t *testing.T) {
	d := det(t)
	hits, _ := d.ScanOne(context.Background(), "ghp_NqVwYS81VP7Hb1DX8pQ2mZ7xL4kR9tWcB3vE // gitleaks:allow betterleaks:allow")
	if len(hits) != 1 {
		t.Fatalf("allow signature must not suppress: %+v", hits)
	}
}

func TestEnvDump(t *testing.T) {
	d := det(t)
	env := strings.Join([]string{
		"OPENAI_API_KEY=sk-proj-AbCdEf1234567890GhIjKlMnOpQrStUvWx",
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY",
		"DATABASE_URL=postgresql://app:S3cr3tP%40ssw0rd@db.prod.internal:5432/app",
		"REDIS_URL=redis://:RedisPass123@cache:6379",
		"SMTP_PASSWORD=hunter2SuperSecret!",
		"POSTGRES_PASSWORD=pgSuperSecret99",
		"API_TOKEN=Zx8Kq2Lm9Pw4Rt7Yv3Bn6Hs1Jd5Gf0Ac",
		"DD_API_KEY=1234567890abcdef1234567890abcdef",
		"ENCRYPTION_KEY=3f2a9c1b8d7e6f5a4b3c2d1e0f9a8b7c",
		"LOG_LEVEL=debug",
		"TOKEN_TTL=3600",
	}, "\n")
	hits, err := d.ScanOne(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, h := range hits {
		found[h.Value] = true
	}
	for _, line := range strings.Split(env, "\n") {
		name, val, _ := strings.Cut(line, "=")
		secret := val
		switch name {
		case "DATABASE_URL":
			secret = "S3cr3tP%40ssw0rd"
		case "REDIS_URL":
			secret = "RedisPass123"
		case "LOG_LEVEL", "TOKEN_TTL":
			if found[val] {
				t.Errorf("%s value should not be a secret", name)
			}
			continue
		}
		if !found[secret] {
			t.Errorf("%s: %q not detected (hits %v)", name, secret, keys(found))
		}
	}
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestNoFalsePositivesOnCode(t *testing.T) {
	d := det(t)
	code := `import os
VAULT_KEY_SOURCE = "file"
DEFAULT_MODEL = "claude-sonnet-4-5-20250929"
commit = "3f2a9c1b8d7e6f5a4b3c2d1e0f9a8b7c9d8e7f6a"
uuid = "550e8400-e29b-41d4-a716-446655440000"
image = "ghcr.io/acme/gateway@sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
pkg = "@deepseek-ai/dsh-hooks-claude-code@0.2.1-alpha.4"
path = "/home/user/projects/keycordon/internal/detector/detector.go"
ts = "2026-11-14T14:39:09.123Z"
call = "call_8fKq2Lm9Pw4Rt7Yv3Bn6Hs"
TOKEN_TTL = 3600
api_key = os.environ["OPENAI_API_KEY"]
password = "${DB_PASSWORD}"
`
	hits, err := d.ScanOne(context.Background(), code)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hits {
		t.Errorf("false positive: %s %q", h.RuleID, h.Value)
	}
}

func TestMerge(t *testing.T) {
	s := "0123456789"
	got := Merge(s, []Hit{{Start: 5, End: 8}, {Start: 1, End: 3}, {Start: 2, End: 6}})
	if len(got) != 1 || got[0].Start != 1 || got[0].End != 8 || got[0].Value != "1234567" {
		t.Fatalf("%+v", got)
	}
}

func TestLocationRange(t *testing.T) {
	s := "ab\ncdef\ng"
	a, b, ok := locationRange(s, report.Location{StartLine: 2, StartColumn: 2, EndLine: 2, EndColumn: 3})
	if !ok || s[a:b] != "de" {
		t.Fatalf("%d %d %v", a, b, ok)
	}
}

func BenchmarkScan100KB(b *testing.B) {
	d := det(b)
	text := strings.Repeat("The quick brown fox jumps over the lazy dog. ", 2300)
	b.SetBytes(int64(len(text)))
	for b.Loop() {
		if _, err := d.ScanOne(context.Background(), text); err != nil {
			b.Fatal(err)
		}
	}
}

func TestURIPasswordNotSwallowingHost(t *testing.T) {
	d := det(t)
	s := "db: postgres://u:Sup3rS3cretPw@db.internal/x"
	hits, err := d.ScanOne(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Value != "Sup3rS3cretPw" {
		t.Fatalf("hits = %+v", hits)
	}
}

// CJK labels are matched natively (cjk.go), not by a betterleaks rule: a
// keyword-gated rule cannot fire on multi-byte text. These are the cases the
// TOML rule used to cover, plus the ones that must stay unmasked.
func TestCJKLabels(t *testing.T) {
	d := det(t)
	cases := []struct {
		in   string
		want string // "" means nothing is masked
	}{
		{"数据库密码是 hunter2-but-longer", "hunter2-but-longer"},
		{"密码是 hunter2-but-longer", "hunter2-but-longer"},
		{"口令：Zq7xLm2Vp9r", "Zq7xLm2Vp9r"},
		{"秘钥 sk-live-9f8a7b6c5d4e3f2a1b0c", "sk-live-9f8a7b6c5d4e3f2a1b0c"},
		{"数据库密码是 correcthorsebattery", "correcthorsebattery"},
		{"登录口令是 changeme2024", "changeme2024"},
		{"密碼：Zq7xLm2Vp9r", "Zq7xLm2Vp9r"},
		{"パスワード: Zq7xLm2Vp9r", "Zq7xLm2Vp9r"},
		{"비밀번호: hunter2butlonger", "hunter2butlonger"},
		{"私钥 abcdefgh", "abcdefgh"},
		{"安全码 A1b2C3d4", "A1b2C3d4"},
		// Must stay as written.
		{"密码是必需的字段", ""},
		{"密码是 12345678 位数", ""},
		{"密码是 password 字段", ""},
		{"密码是 required", ""},
		{"这个密码是 string 类型", ""},
	}
	for _, c := range cases {
		hits, err := d.ScanOne(context.Background(), c.in)
		if err != nil {
			t.Fatal(err)
		}
		if c.want == "" {
			if len(hits) != 0 {
				t.Errorf("%q: masked %+v, want nothing", c.in, hits)
			}
			continue
		}
		found := false
		for _, h := range hits {
			if h.Value == c.want {
				found = true
			}
		}
		if !found {
			t.Errorf("%q: %q not found in %+v", c.in, c.want, hits)
		}
	}
}
