// Package oauthmngr implements Holepunch's OAuth2 session-management strategies for
// fronting oauth2-proxy. It exposes a single Validator interface with three
// implementations, selected via --oauth-strategy:
//
//   - none (default, none.go): a no-op that rejects any attempt to use OAuth2, for
//     deployments that don't need it.
//   - oauth2-proxy-reverse (op-reverse.go): for oauth2-proxy running with
//     reverse_proxy=true behind wildcard DNS. Holepunch just routes /-/wormhole/oauth2/*
//     to oauth2-proxy and lets it set its own cookie on each subdomain directly - no
//     nonce or session state is needed on this side.
//   - oauth2-proxy-middleware (op-middleware.go): for identity providers that can't do
//     wildcard redirects. The flow bounces through a single auth domain
//     (--oauth-user-auth-url): a nonce bound to the requesting client's IP and target
//     subdomain is generated and stored (nonce.go), the auth-domain callback captures
//     the oauth2-proxy session cookie against that nonce, and the subdomain callback
//     redeems it - validating the binding - before issuing a subdomain-scoped cookie
//     (--oauth-cookie-name, --oauth-cookie-max-age). Nonces and captured session data
//     are single-use, enforced with compare-and-swap against the KV store, and expire
//     after --oauth-nonce-ttl.
//
// Validator's methods cover the full request lifecycle: ExpandSources injects any
// routes a strategy needs into the route registry, EstablishPreAuthFunc lets specific
// requests (e.g. the oauth2-proxy or callback endpoints) skip Holepunch's own auth
// check, PrepareAuthRedirect builds the redirect that kicks off a flow, RedirectHandler
// processes the /-/wormhole/oauthmngr callback, and ValidateCookies extracts an access
// token from an already-authenticated request's cookies.
package oauthmngr

import (
	"context"
	"fmt"
	"net/http"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/ctls/errs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
	"github.com/llnl/wormhole-holepunch/internal/ctls/streams"
	"github.com/llnl/wormhole-holepunch/internal/wormhole"
)

const (
	managerPath         = "/oauthmngr"
	oauth2ProxyBasePath = "/oauth2"

	StrategyNone                  = "none"
	StrategyOauth2ProxyReverse    = "oauth2-proxy-reverse"
	StrategyOauth2ProxyMiddleware = "oauth2-proxy-middleware"
)

type Result struct {
	AccessToken string
	// CookieHeader is the request's Cookie header with any cookie owned by Holepunch (or by
	// oauth2-proxy, for the reverse strategy) stripped out. Callers should forward this in
	// place of the original Cookie header so that cookie is never exposed upstream.
	CookieHeader string
}

type Validator interface {
	// ExpandSources offers an opportunity to expand the route registry (and static) provided
	// configurations to include additional routes that may be required to support the required
	// Oauth2 flow. Regardless off the proxy service (e.g., Envoy) these configuration will
	// be observed and enforced as any traditional route. It is the responsibility of the
	// function implementor to ensure that injected routes live within the pre-approved
	// paths (e.g., /-/wormhole/*).
	ExpandSources(
		rawSources []wormhole.RawSource,
	) []wormhole.RawSource

	// EstablishPreAuthFunc returns a function that will be called prior to any request being
	// authenticated by the Holepunch Auth service. It will align session management with the
	// admin configuration, using the StatusError to assist in redirects when required. Additionally,
	// the returned boolean indicates whether the request should be allowed to skip the remaining
	// auth flow, thus relying on the upstream Oauth2 service to handle the request.
	EstablishPreAuthFunc(
		source wormhole.RawSource,
	) func(requests.RequestDetails) (bool, *errs.StatusError)

	// PrepareAuthRedirect creates the redirect URL to initiate the OAuth flow for an unauthenticated
	// request. Takes the proposed redirect destination and request details, generates a nonce bound
	// to the request characteristics, stores the nonce with the OAuth flow. This ensures nonces
	// are created and injected when required. It is required that the caller has properly validated
	// the prosedRedirect URL against the configured route registry to avoid malicious redirection.
	PrepareAuthRedirect(
		proposedRedirect string,
		details requests.RequestDetails,
	) (string, *errs.StatusError)

	// RedirectHandler processes requests to the `/-/wormhole/oauthmngr` callback endpoint.
	// Validates nonces, retrieves stored session state, issues subdomain-scoped cookies, and
	// returns the final redirect URL. This method isolates callback-specific logic from the
	// general pre-auth flow.
	RedirectHandler(
		ctx context.Context,
		details requests.RequestDetails,
	) (*http.Cookie, *errs.StatusError)

	// ValidateCookies validates the required cookies for a given request, read from the
	// Cookie header in details.Headers, against the underlying Oauth2 flow. The resulting
	// access_token is returned, it's the responsibility of the caller to correctly exchange
	// this access_token for the equivalent Jump Token via the Token Service. See
	// Result.CookieHeader for the header the caller should forward in place of the original.
	ValidateCookies(
		ctx context.Context,
		details requests.RequestDetails,
	) (Result, *errs.StatusError)
}

func Initialize(
	kvStore streams.KVStore,
	ll logs.Logger,
	oauthArgs args.OauthManagement,
) (Validator, error) {
	switch oauthArgs.Strategy {
	case StrategyNone, "":
		ll.Infof("initializing OAuth: strategy=%s", StrategyNone)

		return newNoneManager(), nil

	case StrategyOauth2ProxyReverse:
		ll.Infof("initializing OAuth: strategy=%s", StrategyOauth2ProxyReverse)

		validator, err := newOauth2ProxyReverseManager(ll, oauthArgs)
		if err != nil {
			return nil, err
		}

		ll.Infof(
			"OAuth reverse proxy initialized (internal=%s)",
			oauthArgs.InternalProxyURL,
		)

		return validator, nil

	case StrategyOauth2ProxyMiddleware:
		ll.Infof("initializing OAuth: strategy=%s", StrategyOauth2ProxyMiddleware)

		validator, err := newOauth2ProxyMiddlewareManager(kvStore, ll, oauthArgs)
		if err != nil {
			return nil, err
		}

		ll.Infof(
			"OAuth middleware initialized (internal=%s, user_auth=%s, cookie_max_age=%ds)",
			oauthArgs.InternalProxyURL,
			oauthArgs.UserAuthURL,
			oauthArgs.CookieMaxAge,
		)

		return validator, nil

	default:
		return nil, fmt.Errorf(
			"invalid OAuth strategy: %s (valid options: %s, %s, %s)",
			oauthArgs.Strategy,
			StrategyNone,
			StrategyOauth2ProxyReverse,
			StrategyOauth2ProxyMiddleware,
		)
	}
}
