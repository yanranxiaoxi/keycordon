// Package config loads the keycordon YAML configuration.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"time"

	"go.yaml.in/yaml/v3"
)

// Config is the full configuration. Zero values are replaced by defaults.
type Config struct {
	Listen   string `yaml:"listen"`
	Upstream string `yaml:"upstream"`
	// Mode is "enforce" (replace and restore) or "observe" (log only).
	Mode string `yaml:"mode"`
	// PreserveHost forwards the client's Host header instead of the
	// upstream's.
	PreserveHost       bool `yaml:"preserve_host"`
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`

	Limits    Limits    `yaml:"limits"`
	Protocols Protocols `yaml:"protocols"`
	Request   Request   `yaml:"request"`
	Detector  Detector  `yaml:"detector"`
	Restore   Restore   `yaml:"restore"`
	Caller    Caller    `yaml:"caller"`
	Vault     Vault     `yaml:"vault"`
	Log       Log       `yaml:"log"`
}

type Limits struct {
	MaxBodyBytes     int64         `yaml:"max_body_bytes"`
	MaxDecodedBytes  int64         `yaml:"max_decoded_bytes"`
	MaxResponseBytes int64         `yaml:"max_response_bytes"`
	MaxJSONDepth     int           `yaml:"max_json_depth"`
	ScanTimeout      time.Duration `yaml:"scan_timeout"`
}

type Protocols struct {
	Enabled  []string `yaml:"enabled"`
	ExtraDir string   `yaml:"extra_dir"`
	// UnsupportedPolicy is "reject" or "passthrough" for WebSocket and
	// other AI transports keycordon cannot filter.
	UnsupportedPolicy  string `yaml:"unsupported_ai_policy"`
	DetectUnregistered *bool  `yaml:"detect_unregistered"`
}

type Request struct {
	InjectInstruction *bool `yaml:"inject_instruction"`
	InjectAlways      *bool `yaml:"inject_always"`
}

type Detector struct {
	RulesFile      string `yaml:"rules_file"`
	MaxDecodeDepth *int   `yaml:"max_decode_depth"`
	MinValueLength int    `yaml:"min_value_length"`
}

type Restore struct {
	Enabled *bool `yaml:"enabled"`
}

type Caller struct {
	RequireOnNonLoopback *bool `yaml:"require_on_non_loopback"`
}

type Vault struct {
	MasterKeyScope      string        `yaml:"master_key_scope"`
	MasterKeyFile       string        `yaml:"master_key_file"`
	MasterKeyEnv        string        `yaml:"master_key_env"`
	MaxEntriesPerCaller int           `yaml:"max_entries_per_caller"`
	IdleTTL             time.Duration `yaml:"idle_ttl"`
	// MaxSentTexts bounds the memo of texts already sent, which freezes
	// their spans so a value that becomes known later never rewrites
	// history (design 7.8).
	MaxSentTexts int `yaml:"max_sent_texts"`
}

type Log struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

func ptr[T any](v T) *T { return &v }

// Default returns the default configuration.
func Default() *Config {
	c := &Config{}
	c.applyDefaults()
	return c
}

func (c *Config) applyDefaults() {
	def := func(s *string, v string) {
		if *s == "" {
			*s = v
		}
	}
	def(&c.Listen, "127.0.0.1:8318")
	def(&c.Upstream, "http://127.0.0.1:8317")
	def(&c.Mode, "enforce")
	// Sized for a 2M-token text request, which is 3-11 MiB depending on the
	// content (design 11.4), with room for the JSON envelope. A request with
	// several images will need more: a model bills images per tile, so ten
	// 4 MiB PNGs is a 53 MiB body.
	if c.Limits.MaxBodyBytes == 0 {
		c.Limits.MaxBodyBytes = 8 << 20
	}
	// Twice the body limit: a request may arrive compressed, and gzip on JSON
	// can expand 5-8x.
	if c.Limits.MaxDecodedBytes == 0 {
		c.Limits.MaxDecodedBytes = 16 << 20
	}
	if c.Limits.MaxResponseBytes == 0 {
		c.Limits.MaxResponseBytes = 16 << 20
	}
	if c.Limits.MaxJSONDepth == 0 {
		c.Limits.MaxJSONDepth = 128
	}
	if c.Limits.ScanTimeout == 0 {
		c.Limits.ScanTimeout = 2 * time.Second
	}
	if len(c.Protocols.Enabled) == 0 {
		c.Protocols.Enabled = nil
	}
	def(&c.Protocols.UnsupportedPolicy, "reject")
	def(&c.Protocols.ExtraDir, "~/.config/keycordon/protocols")
	if c.Protocols.DetectUnregistered == nil {
		c.Protocols.DetectUnregistered = ptr(true)
	}
	if c.Request.InjectInstruction == nil {
		c.Request.InjectInstruction = ptr(true)
	}
	if c.Request.InjectAlways == nil {
		c.Request.InjectAlways = ptr(true)
	}
	if c.Detector.MaxDecodeDepth == nil {
		c.Detector.MaxDecodeDepth = ptr(2)
	}
	if c.Detector.MinValueLength == 0 {
		c.Detector.MinValueLength = 8
	}
	if c.Restore.Enabled == nil {
		c.Restore.Enabled = ptr(true)
	}
	if c.Caller.RequireOnNonLoopback == nil {
		c.Caller.RequireOnNonLoopback = ptr(true)
	}
	def(&c.Vault.MasterKeyScope, "file")
	def(&c.Vault.MasterKeyFile, "~/.config/keycordon/master.key")
	def(&c.Vault.MasterKeyEnv, "KEYCORDON_MASTER_KEY")
	if c.Vault.MaxEntriesPerCaller == 0 {
		c.Vault.MaxEntriesPerCaller = 10000
	}
	if c.Vault.IdleTTL == 0 {
		c.Vault.IdleTTL = 24 * time.Hour
	}
	if c.Vault.MaxSentTexts == 0 {
		c.Vault.MaxSentTexts = 1 << 16
	}
	def(&c.Log.Level, "info")
	def(&c.Log.Format, "text")
}

// Load reads a YAML file. An empty path returns the defaults.
func Load(path string) (*Config, error) {
	c := &Config{}
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(c); err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("config %s: %w", path, err)
		}
	}
	c.applyDefaults()
	return c, c.Validate()
}

// Validate checks the configuration.
func (c *Config) Validate() error {
	var errs []error
	if c.Mode != "enforce" && c.Mode != "observe" {
		errs = append(errs, fmt.Errorf("mode must be enforce or observe"))
	}
	if u, err := url.Parse(c.Upstream); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		errs = append(errs, fmt.Errorf("upstream must be an http(s) URL"))
	}
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		errs = append(errs, fmt.Errorf("listen: %w", err))
	}
	if p := c.Protocols.UnsupportedPolicy; p != "reject" && p != "passthrough" {
		errs = append(errs, fmt.Errorf("protocols.unsupported_ai_policy must be reject or passthrough"))
	}
	switch c.Vault.MasterKeyScope {
	case "file", "env", "process":
	default:
		errs = append(errs, fmt.Errorf("vault.master_key_scope must be file, env or process"))
	}
	if c.Limits.MaxJSONDepth < 8 {
		errs = append(errs, fmt.Errorf("limits.max_json_depth too small"))
	}
	// A negative limit would make every body "too large" (the reader gets a
	// negative budget) or, worse, disable the check entirely. Zero means
	// "use the default", which applyDefaults has already filled in.
	for _, l := range []struct {
		name string
		v    int64
	}{
		{"limits.max_body_bytes", c.Limits.MaxBodyBytes},
		{"limits.max_decoded_bytes", c.Limits.MaxDecodedBytes},
		{"limits.max_response_bytes", c.Limits.MaxResponseBytes},
	} {
		if l.v < 0 {
			errs = append(errs, fmt.Errorf("%s must not be negative", l.name))
		}
	}
	if c.Limits.ScanTimeout < 0 {
		errs = append(errs, fmt.Errorf("limits.scan_timeout must not be negative"))
	}
	return errors.Join(errs...)
}

// ListenIsLoopback reports whether the listen address only accepts local
// connections.
func (c *Config) ListenIsLoopback() bool {
	host, _, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
