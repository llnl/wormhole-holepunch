package keys

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

const (
	/*
		Static request/response headers provided or directly interfaced with
		by Holepunch. All headers are set to lower case to realize compatibility
		with a range of different interfaces.
	*/

	CookieHeader                 = "cookie"
	CommunityHeader              = "x-wormhole-community"
	Oauth2ProxyAccessTokenHeader = "x-auth-request-access-token" // nolint: gosec
	PikoHeader                   = "x-piko-endpoint"
	RequestIDHeader              = "x-request-id"
	SetCookieHeader              = "set-cookie"
	TraceparentHeader            = "traceparent"
	VersionHeader                = "x-holepunch-version"
	XForwardHostHeader           = "x-forwarded-host"
	XForwardProtoHeader          = "x-forwarded-proto"
	XForwardURIHeader            = "x-forwarded-uri"
	WormholeHostHeader           = "x-wormhole-host"
	WormholeSchemeHeader         = "x-wormhole-scheme"
)

// DefaultRemovableHeaders returns a list of headers that are considered removable from
// a user request by default. These headers are typically used for internal purposes and
// may not be relevant for all external clients.
func DefaultRemovableHeaders() []string {
	return []string{
		CommunityHeader,
		Oauth2ProxyAccessTokenHeader,
		PikoHeader,
		VersionHeader,
		WormholeHostHeader,
		WormholeSchemeHeader,
	}
}

// WormholeAccessToken generates the key for use in caching.
func WormholeAccessToken(tokenID string) string {
	return "wat.v1." + base64.RawURLEncoding.EncodeToString([]byte(tokenID))
}

// WormholeOauthSession generates the key for use in caching.
func WormholeOauthSession(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken)) // returns [32]byte
	return "wos.v1-" + hex.EncodeToString(sum[:])
}

// WormholeAccessSubtoken generates the key for use in caching.
func WormholeAccessSubtoken(parentID, externalID string) string {
	return fmt.Sprintf(
		"was.v1.%s.%s",
		base64.RawURLEncoding.EncodeToString([]byte(parentID)),
		base64.RawURLEncoding.EncodeToString([]byte(externalID)),
	)
}
