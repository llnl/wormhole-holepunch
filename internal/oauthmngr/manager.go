// Package oauthmngr manages OAuth2 sessions through oauth2-proxy, exposing a Validator
// selected by --oauth-strategy:
//
//   - none (default): disables OAuth2 flows.
//   - oauth2-proxy-reverse: routes authentication through oauth2-proxy on each sub-domain
//     using reverse_proxy=true and wildcard DNS, without a ledger.
//   - oauth2-proxy-middleware: uses a single auth domain for providers without wildcard
//     redirects; a request-bound nonce and the session ledger's callback transfer the
//     session to a host-only cookie on the target sub-domain.
//
// ExpandSources adds OAuth routes with authentication bypasses rendered by xDS;
// Holepunch Auth (ext_authz) authenticates requests rather than selecting those routes.
// See docs/oauth-manager.md for configuration and flow details.
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
	"github.com/llnl/wormhole-holepunch/internal/wormhole/registry"
)

const (
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

// AuthRedirect describes the redirect that starts an OAuth flow and any response cookie
// needed to bind that flow to the initiating browser.
type AuthRedirect struct {
	URL       string
	SetCookie *http.Cookie
}

type Validator interface {
	// ExpandSources preserves application sources and adds each required OAuth route kind
	// once per hostname, regardless of paths, ports, or schemes.
	// It does not reserve the entire /-/wormhole/ prefix.
	ExpandSources(
		rawSources []registry.RawSource,
	) []registry.RawSource

	// PrepareAuthRedirect starts an OAuth flow, storing a request-bound nonce and target
	// destination when required by the strategy.
	// The caller must first validate proposedRedirect using the route registry's AllowedRedirect.
	PrepareAuthRedirect(
		proposedRedirect string,
		details requests.RequestDetails,
	) (AuthRedirect, *errs.StatusError)

	// ValidateCookies resolves the Cookie header in details.Headers to an OAuth access token.
	// The caller must exchange it for a Jump Token via the Token Service and forward
	// Result.CookieHeader instead of the original header.
	ValidateCookies(
		ctx context.Context,
		details requests.RequestDetails,
	) (Result, *errs.StatusError)
}

// Disabled returns a none-strategy Validator for components that do not participate in OAuth flows.
func Disabled() Validator {
	return newNoneManager()
}

// Initialize returns a Validator for the configured strategy.
// The client resolves oauth2-proxy sessions, and the KV store holds middleware nonces.
func Initialize(
	kvStore streams.KVStore,
	client requests.Client,
	ll logs.Logger,
	oauthArgs args.OauthManagement,
) (Validator, error) {
	switch oauthArgs.Strategy {
	case StrategyNone, "":
		ll.Infof("initializing OAuth: strategy=%s", StrategyNone)

		return newNoneManager(), nil

	case StrategyOauth2ProxyReverse:
		ll.Infof("initializing OAuth: strategy=%s", StrategyOauth2ProxyReverse)

		validator, err := newReverseManager(client, ll, oauthArgs)
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

		validator, err := newMiddlewareManager(kvStore, client, ll, oauthArgs)
		if err != nil {
			return nil, err
		}

		ll.Infof(
			"OAuth middleware initialized (internal=%s, user_auth=%s, ledger=%s, cookie_max_age=%ds, disable_client_ip_check=%t)",
			oauthArgs.InternalProxyURL,
			oauthArgs.UserAuthURL,
			oauthArgs.OauthLedgerURL,
			oauthArgs.CookieMaxAge,
			oauthArgs.DisableClientIPCheck,
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
