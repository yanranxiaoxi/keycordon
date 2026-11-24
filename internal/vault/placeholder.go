package vault

import (
	"regexp"
	"strings"
)

// PlaceholderMarker is the fixed start of every placeholder.
const PlaceholderMarker = "<SECRET_"

// MaxPlaceholderLen bounds the length of a placeholder.
const MaxPlaceholderLen = len(PlaceholderMarker) + 32 + 1 + 64 + 1

var placeholderRE = regexp.MustCompile(`<SECRET_[A-Z0-9_]{1,32}_[0-9a-f]{8,64}>`)

// FindPlaceholders returns the [start, end) offsets of placeholders in s.
func FindPlaceholders(s string) [][]int {
	if !strings.Contains(s, PlaceholderMarker) {
		return nil
	}
	return placeholderRE.FindAllStringIndex(s, -1)
}

// IsPlaceholder reports whether s is exactly one placeholder.
func IsPlaceholder(s string) bool {
	loc := placeholderRE.FindStringIndex(s)
	return loc != nil && loc[0] == 0 && loc[1] == len(s)
}

// CouldBePlaceholderPrefix reports whether s (starting with '<') may grow
// into a placeholder. It is deliberately permissive: a false positive only
// delays output by one event.
func CouldBePlaceholderPrefix(s string) bool {
	if len(s) == 0 || len(s) >= MaxPlaceholderLen {
		return false
	}
	if len(s) <= len(PlaceholderMarker) {
		return strings.HasPrefix(PlaceholderMarker, s)
	}
	if !strings.HasPrefix(s, PlaceholderMarker) {
		return false
	}
	for i := len(PlaceholderMarker); i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// PendingTail returns the length of the longest suffix of s that could
// still become a placeholder once more text arrives.
func PendingTail(s string) int {
	start := len(s) - MaxPlaceholderLen + 1
	if start < 0 {
		start = 0
	}
	for i := start; i < len(s); i++ {
		if s[i] == '<' && CouldBePlaceholderPrefix(s[i:]) {
			return len(s) - i
		}
	}
	return 0
}
