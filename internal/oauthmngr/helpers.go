package oauthmngr

import (
	"net/url"
	"strings"

	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
)

// targetURLFromDetails reconstructs the originally-requested URL (scheme, host, path) from
// details, for use as the destination to return to once an OAuth flow completes.
func targetURLFromDetails(details requests.RequestDetails) string {
	scheme := details.Scheme
	if scheme == "" {
		scheme = "https"
	}

	target := url.URL{
		Scheme: scheme,
		Host:   details.Host,
		Path:   details.Path,
	}

	return target.String()
}

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
// remaining "name=value" pairs intact.
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
