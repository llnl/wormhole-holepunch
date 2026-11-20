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

	AccessControlAllowCredentialsHeader = "access-control-allow-credentials"
	AccessControlAllowHeadersHeader     = "access-control-allow-headers"
	AccessControlAllowMethodsHeader     = "access-control-allow-methods"
	AccessControlAllowOriginHeader      = "access-control-allow-origin"
	AccessControlRequestHeadersHeader   = "access-control-request-headers"
	AccessControlRequestMethodHeader    = "access-control-request-method"
	AllowHeader                         = "allow"
	CacheControlHeader                  = "cache-control"
	ContentTypeHeader                   = "content-type"
	ContentTypeOptionsHeader            = "x-content-type-options"
	CookieHeader                        = "cookie"
	CommunityHeader                     = "x-wormhole-community"
	LocationHeader                      = "location"
	Oauth2ProxyAccessTokenHeader        = "x-auth-request-access-token" // nolint: gosec
	OriginHeader                        = "origin"
	ReferrerPolicyHeader                = "referrer-policy"
	RequestIDHeader                     = "x-request-id"
	// RouteIDHeader identifies the registry route a request should be directed to. The
	// value is retained for compatibility with the upstream tunnel (Piko).
	RouteIDHeader               = "x-piko-endpoint"
	SecFetchSiteHeader          = "sec-fetch-site"
	SetCookieHeader             = "set-cookie"
	TraceparentHeader           = "traceparent"
	VaryHeader                  = "vary"
	VersionHeader               = "x-holepunch-version"
	XForwardHostHeader          = "x-forwarded-host"
	XForwardProtoHeader         = "x-forwarded-proto"
	XForwardURIHeader           = "x-forwarded-uri"
	WormholeHostHeader          = "x-wormhole-host"
	WormholeOAuthCodeHeader     = "x-wormhole-oauth-code"
	WormholeOAuthProofHeader    = "x-wormhole-oauth-proof"
	WormholeSchemeHeader        = "x-wormhole-scheme"
	ContentSecurityPolicyHeader = "content-security-policy"
)

// DefaultRemovableHeaders returns a list of headers that are considered removable from
// a user request by default. These headers are typically used for internal purposes and
// may not be relevant for all external clients.
func DefaultRemovableHeaders() []string {
	return []string{
		CommunityHeader,
		Oauth2ProxyAccessTokenHeader,
		RouteIDHeader,
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
