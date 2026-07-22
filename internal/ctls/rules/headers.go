package rules

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
)

var disallowedHeaders = map[string]bool{
	"host":                        true,
	"x-forwarded-for":             true,
	"x-real-ip":                   true,
	"x-envoy-internal":            true,
	"x-envoy-decorator-operation": true,
}

// ValidateHeaderName verified the proposed header name before injecting it
// into a request/response. The values passed to this should be either proposed
// by route owners or other semi-automated processes.
func ValidateHeaderName(name string) error {
	lower := strings.ToLower(name)
	if disallowedHeaders[lower] {
		return fmt.Errorf("header %s is not allowed", name)
	}

	// RFC 7230 token validation
	for _, ch := range name {
		if !isTokenChar(ch) {
			return fmt.Errorf("invalid header name: %s", name)
		}
	}

	return nil
}

// ValidateHeaderValue verified the proposed header value before injecting it
// into a request/response.
func ValidateHeaderValue(value string) error {
	for _, ch := range value {
		// No control characters except HTAB
		if unicode.IsControl(ch) && ch != '\t' {
			return errors.New("invalid control character in header value")
		}
	}

	return nil
}

//

// isTokenChar reports whether ch is a valid RFC 7230 "tchar" for header
// field-names.
func isTokenChar(ch rune) bool {
	// ALPHA
	if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') {
		return true
	}

	// DIGIT
	if ch >= '0' && ch <= '9' {
		return true
	}

	switch ch {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	default:
		return false
	}
}
