package vault

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// MasterKeySize is the size of a generated master key.
const MasterKeySize = 32

// Scope selects where the master key comes from.
type Scope string

const (
	ScopeFile    Scope = "file"
	ScopeEnv     Scope = "env"
	ScopeProcess Scope = "process"
)

// KeySource describes how to obtain the master key.
type KeySource struct {
	Scope   Scope
	File    string
	EnvName string
}

// LoadMasterKey returns the master key for src. With ScopeFile the key is
// generated on first use and written with mode 0600. An environment variable
// named by EnvName takes precedence over the file when set.
func LoadMasterKey(src KeySource) ([]byte, error) {
	switch src.Scope {
	case ScopeProcess:
		return randomKey()
	case ScopeEnv, ScopeFile, "":
	default:
		return nil, fmt.Errorf("vault: unknown master key scope %q", src.Scope)
	}
	if src.EnvName != "" {
		if v, ok := os.LookupEnv(src.EnvName); ok && strings.TrimSpace(v) != "" {
			return decodeKey(v)
		}
	}
	if src.Scope == ScopeEnv {
		return nil, fmt.Errorf("vault: environment variable %s is not set", src.EnvName)
	}
	if src.File == "" {
		return nil, errors.New("vault: master key file not configured")
	}
	path, err := ExpandHome(src.File)
	if err != nil {
		return nil, err
	}
	return loadOrCreateFile(path)
}

func loadOrCreateFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		if info, serr := os.Stat(path); serr == nil && info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("vault: %s must not be accessible by group or others (mode %v)", path, info.Mode().Perm())
		}
		return decodeKey(string(data))
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("vault: read master key: %w", err)
	}
	key, err := randomKey()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("vault: create key directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		// Another process created it first.
		return loadOrCreateFile(path)
	}
	if err != nil {
		return nil, fmt.Errorf("vault: create master key: %w", err)
	}
	_, werr := f.WriteString(hex.EncodeToString(key) + "\n")
	cerr := f.Close()
	if werr != nil || cerr != nil {
		os.Remove(path)
		return nil, fmt.Errorf("vault: write master key: %w", errors.Join(werr, cerr))
	}
	return key, nil
}

func randomKey() ([]byte, error) {
	key := make([]byte, MasterKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("vault: random: %w", err)
	}
	return key, nil
}

// decodeKey accepts hex or base64 and requires at least 32 bytes of key.
func decodeKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if b, err := hex.DecodeString(s); err == nil && len(b) >= MasterKeySize {
		return b, nil
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) >= MasterKeySize {
			return b, nil
		}
	}
	return nil, fmt.Errorf("vault: master key must be hex or base64 encoding of at least %d bytes", MasterKeySize)
}

// Fingerprint identifies a master key without revealing it.
func Fingerprint(key []byte) string {
	h := sha256.New()
	h.Write([]byte("keycordon/fingerprint/v1\x00"))
	h.Write(key)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// ExpandHome expands a leading "~/".
func ExpandHome(p string) (string, error) {
	if p != "~" && !strings.HasPrefix(p, "~/") {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("vault: expand %s: %w", p, err)
	}
	return filepath.Join(home, strings.TrimPrefix(p, "~")), nil
}
