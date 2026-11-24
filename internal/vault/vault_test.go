package vault

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

var testMaster = []byte("0123456789abcdef0123456789abcdef")

var phRe = regexp.MustCompile(`^<SECRET_[A-Z0-9_]{1,32}_[0-9a-f]{8,64}>$`)

func TestPlaceholderDeterministic(t *testing.T) {
	v1 := New(testMaster, Options{})
	v2 := New(testMaster, Options{})
	secret := "ghp_NqVwYS81VP7Hb1DX8pQ2mZ7xL4kR9tWcB3vE"
	a := v1.Caller("local").Placeholder(secret)
	b := v2.Caller("local").Placeholder(secret)
	if a != b {
		t.Fatalf("not deterministic across restarts: %s %s", a, b)
	}
	if !phRe.MatchString(a) || !strings.HasPrefix(a, "<SECRET_GITHUB_TOKEN_") || len(a) != len("<SECRET_GITHUB_TOKEN_12345678>") {
		t.Fatalf("bad placeholder %s", a)
	}
	if c := v1.Caller("other").Placeholder(secret); c == a {
		t.Fatal("callers must get different placeholders")
	}
	if d := New([]byte("ffffffffffffffffffffffffffffffff"), Options{}).Caller("local").Placeholder(secret); d == a {
		t.Fatal("master key must affect placeholders")
	}
}

func TestRestoreIsolation(t *testing.T) {
	v := New(testMaster, Options{})
	a := v.Caller(v.CallerID("key-a"))
	b := v.Caller(v.CallerID("key-b"))
	ph := a.Placeholder("s3cr3t-value-1234")
	if got, ok := a.Restore(ph); !ok || got != "s3cr3t-value-1234" {
		t.Fatal("restore failed")
	}
	if _, ok := b.Restore(ph); ok {
		t.Fatal("caller b restored caller a's placeholder")
	}
	if _, ok := a.Restore("<SECRET_TOKEN_00000000>"); ok {
		t.Fatal("unknown placeholder restored")
	}
}

func TestCollisionExtends(t *testing.T) {
	v := New(testMaster, Options{})
	c := v.Caller("local")
	ph := c.Placeholder("value-one-123456")
	// Simulate a collision by planting another value under the same placeholder.
	c.mu.Lock()
	e := c.byValue["value-one-123456"]
	delete(c.byValue, e.value)
	e.value = "planted"
	c.byValue["planted"] = e
	c.mu.Unlock()
	ph2 := c.Placeholder("value-one-123456")
	if ph2 == ph || len(ph2) != len(ph)+4 {
		t.Fatalf("collision not extended: %s %s", ph, ph2)
	}
}

func TestLRUAndTTL(t *testing.T) {
	now := time.Unix(1000, 0)
	v := New(testMaster, Options{MaxEntriesPerCaller: 2, IdleTTL: time.Hour, Now: func() time.Time { return now }})
	c := v.Caller("local")
	p1 := c.Placeholder("aaaaaaaaaaaa1")
	c.Placeholder("bbbbbbbbbbbb2")
	c.Placeholder("cccccccccccc3")
	if _, ok := c.Restore(p1); ok {
		t.Fatal("oldest entry not evicted")
	}
	if p := c.Placeholder("aaaaaaaaaaaa1"); p != p1 {
		t.Fatal("re-added secret changed placeholder")
	}
	now = now.Add(2 * time.Hour)
	v.Sweep()
	if n, e := v.Stats(); n != 0 || e != 0 {
		t.Fatalf("sweep left %d callers %d entries", n, e)
	}
}

func TestFindKnown(t *testing.T) {
	v := New(testMaster, Options{})
	c := v.Caller("local")
	secret := `pa"ss/wo rd+123`
	c.Placeholder(secret)
	for _, s := range []string{
		"curl -H 'X-Token: " + secret + "'",
		`{"password":"pa\"ss/wo rd+123"}`,
		"https://x/?p=" + "pa%22ss%2Fwo+rd%2B123",
		"b64 " + base64.StdEncoding.EncodeToString([]byte(secret)),
	} {
		r := c.FindKnown(s)
		if len(r) != 1 {
			t.Errorf("%q: %v", s, r)
		}
	}
	if r := c.FindKnown("nothing to see"); r != nil {
		t.Fatal(r)
	}
}

func TestMasterKeyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "master.key")
	k1, err := LoadMasterKey(KeySource{Scope: ScopeFile, File: path})
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v err %v", info.Mode(), err)
	}
	k2, err := LoadMasterKey(KeySource{Scope: ScopeFile, File: path})
	if err != nil || string(k1) != string(k2) {
		t.Fatal("key not stable")
	}
	os.Chmod(path, 0o644)
	if _, err := LoadMasterKey(KeySource{Scope: ScopeFile, File: path}); err == nil {
		t.Fatal("world-readable key accepted")
	}
	t.Setenv("KC_TEST_KEY", strings.Repeat("ab", 32))
	k3, err := LoadMasterKey(KeySource{Scope: ScopeFile, File: path, EnvName: "KC_TEST_KEY"})
	if err != nil || len(k3) != 32 || k3[0] != 0xab {
		t.Fatalf("env override: %v", err)
	}
	t.Setenv("KC_TEST_KEY", "short")
	if _, err := LoadMasterKey(KeySource{Scope: ScopeEnv, EnvName: "KC_TEST_KEY"}); err == nil {
		t.Fatal("short key accepted")
	}
	p1, _ := LoadMasterKey(KeySource{Scope: ScopeProcess})
	p2, _ := LoadMasterKey(KeySource{Scope: ScopeProcess})
	if string(p1) == string(p2) {
		t.Fatal("process keys must differ")
	}
	if Fingerprint(k1) == Fingerprint(k3) || len(Fingerprint(k1)) != 16 {
		t.Fatal("fingerprint")
	}
}

func TestKind(t *testing.T) {
	cases := map[string]string{
		"sk-ant-api03-xxx":                    "ANTHROPIC_KEY",
		"sk-proj-abc":                         "OPENAI_KEY",
		"sk-abc":                              "API_KEY",
		"AKIAIOSFODNN7EXAMPLE":                "AWS_KEY",
		"-----BEGIN OPENSSH PRIVATE KEY-----": "PRIVATE_KEY",
		"Zx8Kq2Lm9Pw4Rt7Yv3Bn6Hs1Jd5Gf0Ac":    "TOKEN",
	}
	for in, want := range cases {
		if got := Kind(in); got != want {
			t.Errorf("Kind(%q) = %s want %s", in, got, want)
		}
	}
}
