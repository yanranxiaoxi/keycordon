// Package veto rejects findings that are code, paths, versions or moments
// rather than secrets.
//
// A rule that matches on context ("PASSWORD=", "password is") also matches
// where the value is not a secret at all: a variable name, a file path, a
// package version, an expiry timestamp. Masking those breaks the agent (it
// can no longer read the path it was pointed at) and costs a prompt cache
// rebuild for nothing.
//
// Every check here is a "this is definitely not a secret" test, so a false
// positive only means a value goes as written — the same as before the
// check existed. The trade-off is deliberate: a password that is literally
// a dotted lowercase identifier is not masked.
package veto

import (
	"regexp"
	"strings"
	"unicode"
)

// Reject reports whether s[start:end] is not a secret.
func Reject(s string, start, end int) bool {
	if start < 0 || end > len(s) || start >= end {
		return false
	}
	v := s[start:end]
	return pathValue(v) || versionValue(v) || timestampValue(v) || lineRef(v) ||
		namesASecret(v) || codeChain(v) || nextField(v)
}

// pathRoots are the first segments of a path that is a location, not a
// value. A secret that starts with "/" has a random first segment.
var pathRoots = map[string]bool{
	"home": true, "Users": true, "etc": true, "var": true, "opt": true,
	"usr": true, "root": true, "tmp": true, "mnt": true, "srv": true,
	"private": true, "Library": true, "Applications": true, "System": true,
	"proc": true, "sys": true, "dev": true, "run": true, "boot": true,
}

// pathValue reports a filesystem path: ~/x, ./x, ../x, /home/x, C:\x.
func pathValue(v string) bool {
	if strings.ContainsAny(v, "+=") {
		return false
	}
	for _, p := range []string{"~/", "./", "../"} {
		if strings.HasPrefix(v, p) && len(v) > len(p) {
			return true
		}
	}
	if len(v) >= 3 && v[1] == ':' && (v[2] == '\\' || v[2] == '/') &&
		(v[0] >= 'A' && v[0] <= 'Z' || v[0] >= 'a' && v[0] <= 'z') {
		return true
	}
	if !strings.HasPrefix(v, "/") {
		return false
	}
	first, rest, ok := strings.Cut(v[1:], "/")
	return ok && rest != "" && pathRoots[first]
}

// versionRangeRe is a release's version as a manifest pins it: an optional
// range operator, numbers joined by dots, then pre-release or build parts.
var versionRangeRe = regexp.MustCompile(`^(?:[~^]|[<>=!~]=?|==)?[vV]?\d+(?:\.\d+)+` +
	`(?:[-+._]?(?:(?i:alpha|beta|rc|pre|preview|post|dev|canary|next|nightly|snapshot|release|final|ga|stable|build|incubating)\d*|[abcmABCM]\d+|\d+))*$`)

// versionValue reports a version, which no secret is.
func versionValue(v string) bool { return versionRangeRe.MatchString(v) }

// stampRe is a moment as RFC 3339 writes one, whole or the head of one to
// the hour (a rule's character set has no colon, so it stops there).
var stampRe = regexp.MustCompile(`^\d{4}-\d{1,2}-\d{1,2}[Tt]\d{1,2}(?::\d{1,2}){0,2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:?\d{2})?$`)

// timestampValue reports a moment's writing: an expiry, a renewal.
func timestampValue(v string) bool { return stampRe.MatchString(v) }

// lineRefRe is a line or a range of lines as an editor names them. A bare
// run of digits is not one: it is a plausible weak password.
var lineRefRe = regexp.MustCompile(`^(?:L\d+(?:[-:]\d+)?|\d+[-:]\d+)$`)

// lineRef reports a line reference such as L643-669 or 643:12.
func lineRef(v string) bool { return lineRefRe.MatchString(v) }

// secretWords are the words of a name in code that say it holds a secret.
var secretWords = map[string]bool{
	"password": true, "passwords": true, "passwd": true, "pwd": true, "pass": true,
	"secret": true, "secrets": true, "token": true, "tokens": true,
	"key": true, "keys": true, "apikey": true, "apikeys": true,
	"credential": true, "credentials": true, "auth": true, "private": true,
	"pin": true, "passphrase": true,
}

// identRe is a name in code: letters, digits, _ and ., starting with a
// letter or _.
var identRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*$`)

// namesASecret reports a name in code that says it holds a secret:
// get_access_token_v2, env.SECRET_V2, refreshToken. A key's characters are
// random; a name made of words, one of them token or secret, is a
// function's or a variable's.
func namesASecret(v string) bool {
	if !identRe.MatchString(v) {
		return false
	}
	// A name in code is lower case, or has _ or . in it. A random key with
	// a capital in the middle and no separator is not a name.
	if !unicode.IsLower(rune(v[0])) && !strings.ContainsAny(v, "_.") {
		return false
	}
	words, named := 0, false
	for _, w := range identWords(v) {
		if strings.IndexFunc(w, unicode.IsLetter) < 0 {
			continue
		}
		words++
		if i := strings.IndexAny(w, "0123456789"); i >= 0 {
			w = w[:i] // countTokens4o: Tokens
		}
		if secretWords[strings.ToLower(w)] {
			named = true
		}
	}
	return words >= 2 && named
}

// identWords splits v at _ and ., and where a capital starts a word in
// camelCase (refreshToken2 is refresh and Token2).
func identWords(v string) []string {
	var out []string
	start := 0
	for i := 1; i < len(v); i++ {
		c := v[i]
		if c == '_' || c == '.' {
			out = append(out, v[start:i])
			start = i + 1
			continue
		}
		if c >= 'A' && c <= 'Z' && v[i-1] >= 'a' && v[i-1] <= 'z' {
			out = append(out, v[start:i])
			start = i
		}
	}
	return append(out, v[start:])
}

// codeChainRe is a dotted chain of lowercase identifiers: os.environ,
// os.environ.get, config.settings.database.
var codeChainRe = regexp.MustCompile(`^[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)+$`)

// codeChain reports a dotted lowercase identifier chain, which is code.
func codeChain(v string) bool { return codeChainRe.MatchString(v) }

// nextFieldRe is an assignment of its own: NAME=value, with the value
// non-empty and no second '=' (so base64 padding is not one).
var nextFieldRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*=[^=]`)

// nextField reports a value that is really the next field of a command
// line: UI_PASSWORD= UI_ADDR=127.0.0.1:39117 ./svc, where the rule let a
// space stand after '=' and took UI_ADDR=127.0.0.1 for UI_PASSWORD's
// value.
func nextField(v string) bool { return nextFieldRe.MatchString(v) }
