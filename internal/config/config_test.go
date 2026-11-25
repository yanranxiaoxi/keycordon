package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestExampleMatchesDefaults(t *testing.T) {
	c, err := Load("../../keycordon.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c, Default()) {
		t.Fatalf("example config drifted from defaults:\n%+v\n%+v", c, Default())
	}
}

func TestValidate(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yaml")
	os.WriteFile(bad, []byte("mode: block\nupstream: ftp://x\n"), 0o600)
	if _, err := Load(bad); err == nil {
		t.Fatal("invalid config accepted")
	}
	unknown := filepath.Join(dir, "unknown.yaml")
	os.WriteFile(unknown, []byte("listn: 1\n"), 0o600)
	if _, err := Load(unknown); err == nil {
		t.Fatal("unknown key accepted")
	}
	c := Default()
	if !c.ListenIsLoopback() {
		t.Fatal("default listen must be loopback")
	}
	c.Listen = "0.0.0.0:8318"
	if c.ListenIsLoopback() {
		t.Fatal("0.0.0.0 is not loopback")
	}
}

func TestLimitsValidation(t *testing.T) {
	c := Default()
	base := *c
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Limits.MaxBodyBytes = -1 },
		func(c *Config) { c.Limits.MaxDecodedBytes = -1 },
		func(c *Config) { c.Limits.MaxResponseBytes = -1 },
		func(c *Config) { c.Limits.ScanTimeout = -time.Second },
	} {
		bad := base
		mutate(&bad)
		if err := bad.Validate(); err == nil {
			t.Errorf("negative limit accepted: %+v", bad.Limits)
		}
	}
	// Zero means "use the default", so it must stay valid before applyDefaults
	// has run (Load calls applyDefaults first, but a hand-built Config should
	// not be rejected for leaving them unset).
	if err := Default().Validate(); err != nil {
		t.Fatalf("defaults rejected: %v", err)
	}
}

func TestLimitsDefaults(t *testing.T) {
	c := Default()
	if c.Limits.MaxBodyBytes != 8<<20 {
		t.Errorf("max_body_bytes = %d", c.Limits.MaxBodyBytes)
	}
	if c.Limits.MaxDecodedBytes != 16<<20 {
		t.Errorf("max_decoded_bytes = %d", c.Limits.MaxDecodedBytes)
	}
	if c.Limits.MaxResponseBytes != 16<<20 {
		t.Errorf("max_response_bytes = %d", c.Limits.MaxResponseBytes)
	}
	if c.Limits.MaxJSONDepth != 128 {
		t.Errorf("max_json_depth = %d", c.Limits.MaxJSONDepth)
	}
	if c.Limits.ScanTimeout != 2*time.Second {
		t.Errorf("scan_timeout = %v", c.Limits.ScanTimeout)
	}
}
