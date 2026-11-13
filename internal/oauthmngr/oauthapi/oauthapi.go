// Package oauthapi holds the constants and cookie helpers shared across the oauthmngr
// components (Holepunch Auth, oauth2-proxy session resolution, and the session Ledger).
package oauthapi

import (
	"encoding/base64"
	"strings"
)

const (
	// NonceParam is the callback query parameter carrying the nonce.
	NonceParam = "nonce"
	// BindingCookiePrefix namespaces short-lived browser-binding cookies by nonce.
	BindingCookiePrefix = "_wormhole_oauth_flow_"

	// NonceBytes is the number of random bytes (128 bits) in a nonce.
	NonceBytes = 16
)

// ValidNonce reports whether s is an unpadded URL-safe base64 nonce of NonceBytes bytes.
func ValidNonce(s string) bool {
	b, err := base64.RawURLEncoding.DecodeString(s)

	return err == nil && len(b) == NonceBytes
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
