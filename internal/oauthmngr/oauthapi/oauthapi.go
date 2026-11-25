// Package oauthapi holds the constants and cookie helpers shared across the oauthmngr
// components (Holepunch Auth, oauth2-proxy session resolution, and the session Ledger).
package oauthapi

import (
	"encoding/base64"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

const (
	// NonceParam is the callback query parameter carrying the nonce.
	NonceParam = "nonce"
	// BindingCookiePrefix namespaces short-lived browser-binding cookies by nonce.
	BindingCookiePrefix = "__Host-wormhole_oauth_flow_"
	// AuthProofCookiePrefix identifies the auth host's half of a browser binding.
	AuthProofCookiePrefix = "__Host-wormhole_oauth_auth_"

	// NonceBytes is the number of random bytes (128 bits) in a nonce.
	NonceBytes = 16

	// HostPrefix locks a cookie to a single host. Browsers only accept a __Host- cookie that
	// is Secure, has Path=/, and carries no Domain attribute, so a sibling host on a shared
	// registrable domain cannot set, shadow, or inject a cookie of the same name (cookie
	// tossing). The binding and auth-proof cookie prefixes already begin with it.
	HostPrefix = "__Host-"
)

// HostScopedCookieName reports whether name is locked to a single host by the __Host- prefix.
func HostScopedCookieName(name string) bool {
	return strings.HasPrefix(name, HostPrefix)
}

// HTTPSOrigin returns the canonical https origin for authority, or "" if it is invalid.
func HTTPSOrigin(authority string) string {
	u, err := url.Parse("https://" + authority)
	if err != nil || u.Host != authority || u.User != nil || strings.HasSuffix(authority, ":") {
		return ""
	}

	host := canonicalOriginHost(strings.ToLower(u.Hostname()))
	if host == "" {
		return ""
	}

	if port := u.Port(); port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return ""
		}

		if n != 443 {
			host += ":" + strconv.FormatUint(n, 10)
		}
	}

	return "https://" + host
}

// SameHTTPSAuthority reports whether a and b are valid and share an HTTPSOrigin.
func SameHTTPSAuthority(a, b string) bool {
	origin := HTTPSOrigin(a)

	return origin != "" && origin == HTTPSOrigin(b)
}

// ValidNonce reports whether s is an unpadded URL-safe base64 nonce of NonceBytes bytes.
func ValidNonce(s string) bool {
	b, err := base64.RawURLEncoding.DecodeString(s)

	return err == nil && len(b) == NonceBytes
}

// LogSafeURL returns raw reduced to scheme, host, and path for logging.
func LogSafeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<invalid url>"
	}

	return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path, RawPath: u.RawPath}).String()
}

// HostOnly returns a host or authority without its port, unwrapping bracketed IPv6 literals.
func HostOnly(hostport string) string {
	if rest, ok := strings.CutPrefix(hostport, "["); ok {
		host, _, _ := strings.Cut(rest, "]")

		return host
	}

	if strings.Count(hostport, ":") == 1 {
		host, _, _ := strings.Cut(hostport, ":")

		return host
	}

	return hostport
}

// canonicalOriginHost validates a lowercase hostname or IP, bracketing IPv6. It returns ""
// for invalid or zoned hosts.
func canonicalOriginHost(host string) string {
	if strings.Contains(host, ":") {
		ip, err := netip.ParseAddr(host)
		if err != nil || ip.Zone() != "" {
			return ""
		}

		return "[" + ip.String() + "]"
	}

	for _, r := range host {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '.' {
			return ""
		}
	}

	return host
}
