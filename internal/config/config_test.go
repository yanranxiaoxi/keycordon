package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
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
