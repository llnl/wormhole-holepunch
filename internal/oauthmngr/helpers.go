package oauthmngr

import (
	"net/url"
	"strings"

	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
)

// extractCookie parses the Cookie header and extracts the value of a specific cookie by name.
// Returns empty string if the cookie is not found.
func extractCookie(cookieHeader, cookieName string) string {
	if cookieHeader == "" {
		return ""
	}

	// Parse cookies from the Cookie header
	// Format: "name1=value1; name2=value2; name3=value3"
	for cookie := range strings.SplitSeq(cookieHeader, ";") {
		cookie = strings.TrimSpace(cookie)
		parts := strings.SplitN(cookie, "=", 2)

		if len(parts) == 2 && parts[0] == cookieName {
			return parts[1]
		}
	}

	return ""
}

// removeCookie returns the Cookie header with the named cookie removed, leaving the
// remaining "name=value" pairs intact. Used to strip a Holepunch/oauth2-proxy-owned
// cookie before a request's Cookie header is forwarded upstream.
func removeCookie(cookieHeader, cookieName string) string {
	if cookieHeader == "" {
		return ""
	}

	kept := make([]string, 0)

	for cookie := range strings.SplitSeq(cookieHeader, ";") {
		cookie = strings.TrimSpace(cookie)
		if cookie == "" {
			continue
		}

		parts := strings.SplitN(cookie, "=", 2)
		if len(parts) == 2 && parts[0] == cookieName {
			continue
		}

		kept = append(kept, cookie)
	}

	return strings.Join(kept, "; ")
}

// newURLString creates a URLString from a raw URL string.
// This is a helper to programmatically construct URLString values
// since URLString is normally unmarshaled from JSON.
func newURLString(rawURL string) keys.URLString {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return keys.URLString{}
	}

	return keys.URLString{
		Raw: rawURL,
		Key: normalizeURLKey(parsed),
		URL: parsed,
	}
}

// normalizeURLKey creates a normalized key from a parsed URL (hostname without www prefix)
func normalizeURLKey(parsed *url.URL) string {
	hostname := parsed.Hostname()
	if hostname == "" {
		return parsed.String()
	}

	if len(hostname) > 4 && hostname[:4] == "www." {
		return hostname[4:]
	}

	return hostname
}
