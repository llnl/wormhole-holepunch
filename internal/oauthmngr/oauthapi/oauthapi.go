// Package oauthapi holds the types and constants shared between the oauthmngr control plane
// (Holepunch Auth, xDS, and the session Ledger) and the oauthmngr proxy-wasm plugin. It is
// compiled into the GOOS=wasip1 plugin, so it must remain dependency free beyond the
// standard library.
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

	// LedgerCluster is the Envoy cluster the wasm plugin uses to reach the session Ledger.
	LedgerCluster = "oauthmngr_ledger"
	// LedgerTimeoutMs bounds every Ledger call made by the wasm plugin.
	LedgerTimeoutMs = 2000

	// NonceBytes is the number of random bytes (128 bits) in a nonce.
	NonceBytes = 16
)

// PluginConfig is delivered through xDS as the oauthmngr wasm PluginConfig.configuration.
type PluginConfig struct {
	AuthDomain          string `json:"auth_domain"`
	ProxyCookieName     string `json:"proxy_cookie_name"`
	SessionCookieName   string `json:"session_cookie_name"`
	SessionCookieMaxAge int    `json:"session_cookie_max_age"`
	// ProxySessionStore must match oauth2-proxy's session_store_type, it determines whether
	// chunked cookies are read at the auth domain and issued on the sub-domain.
	ProxySessionStore SessionStore `json:"proxy_session_store"`
	LedgerCluster     string       `json:"ledger_cluster"`
	LedgerTimeoutMs   int          `json:"ledger_timeout_ms"`
}

// CaptureRequest is issued by the wasm plugin at the auth domain.
type CaptureRequest struct {
	Nonce         string `json:"nonce"`
	ClientIP      string `json:"client_ip"`
	Authority     string `json:"authority"`
	SessionCookie string `json:"session_cookie"`
}

// CaptureResponse directs the wasm plugin to the target sub-domain callback.
type CaptureResponse struct {
	TargetSubdomain string `json:"target_subdomain"`
	CallbackURL     string `json:"callback_url"`
}

// RedeemRequest is issued by the wasm plugin at the target sub-domain.
type RedeemRequest struct {
	Nonce         string `json:"nonce"`
	ClientIP      string `json:"client_ip"`
	Authority     string `json:"authority"`
	BindingSecret string `json:"binding_secret"`
}

// RedeemResponse provides the captured session cookie and the user's intended destination.
type RedeemResponse struct {
	SessionCookie string `json:"session_cookie"`
	TargetURL     string `json:"target_url"`
}

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
