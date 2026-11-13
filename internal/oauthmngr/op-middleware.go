package oauthmngr

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/ctls/cookies"
	"github.com/llnl/wormhole-holepunch/internal/ctls/errs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/paths"
	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
	"github.com/llnl/wormhole-holepunch/internal/ctls/streams"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr/ledger"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr/oauthapi"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr/proxyauth"
	"github.com/llnl/wormhole-holepunch/internal/wormhole/registry"
)

const mintTimeout = 5 * time.Second

// middlewareManager implements the Validator interface for the middleware strategy. A single
// oauth2-proxy instance on the auth domain is the redirect target, Holepunch Auth mints the
// nonce that starts the flow, and the Ledger's callback (forwarded by Envoy) hands the
// session across to the target sub-domain as a sub-domain scoped cookie.
type middlewareManager struct {
	ll               logs.Logger
	ledger           *ledger.Store
	proxy            proxyauth.Resolver
	cookieName       string
	internalProxyURL string
	ledgerURL        string
	nonceTTL         int
	sessionStore     oauthapi.SessionStore
	userAuthURL      string
}

func newMiddlewareManager(
	kvStore streams.KVStore,
	client requests.Client,
	ll logs.Logger,
	oauthArgs args.OauthManagement,
) (*middlewareManager, error) {
	if oauthArgs.InternalProxyURL == "" {
		return nil, errors.New("internal URL is required for middleware strategy")
	}

	if oauthArgs.UserAuthURL == "" {
		return nil, errors.New("user auth URL is required for middleware strategy")
	}

	if oauthArgs.OauthLedgerURL == "" {
		return nil, errors.New("ledger URL is required for middleware strategy")
	}

	if oauthArgs.NonceTTL <= 0 {
		return nil, errors.New("a positive nonce TTL is required for middleware strategy")
	}

	store, err := proxyauth.ParseSessionStore(oauthArgs.ProxySessionStore)
	if err != nil {
		return nil, err
	}

	flowStore, err := ledger.New(
		kvStore,
		ll,
		oauthArgs.UserAuthURL,
		time.Duration(oauthArgs.NonceTTL)*time.Second,
	)
	if err != nil {
		return nil, err
	}

	return &middlewareManager{
		ll:               ll,
		ledger:           flowStore,
		proxy:            proxyauth.New(client, ll, oauthArgs.InternalProxyURL, oauthArgs.ProxyCookieName),
		cookieName:       oauthArgs.CookieName,
		internalProxyURL: oauthArgs.InternalProxyURL,
		ledgerURL:        oauthArgs.OauthLedgerURL,
		nonceTTL:         oauthArgs.NonceTTL,
		sessionStore:     store,
		userAuthURL:      oauthArgs.UserAuthURL,
	}, nil
}

//

// ExpandSources adds an oauth2-proxy route on the auth domain and a callback route, forwarded
// to the Ledger, on every virtual host. The auth domain routes are added even when no source
// targets it.
func (o *middlewareManager) ExpandSources(rawSources []registry.RawSource) []registry.RawSource {
	expanded := append([]registry.RawSource{}, rawSources...)

	authDomain := registry.RawSource{Source: urlString("https://" + o.userAuthURL)}

	for _, vh := range virtualHosts(append([]registry.RawSource{authDomain}, rawSources...)) {
		// The auth URL may carry a port (e.g., development), virtual hosts never do.
		if vh.host == oauthapi.HostOnly(o.userAuthURL) {
			expanded = append(expanded,
				newRoute(vh, paths.Oauth2ProxyMiddlewarePrefix, registry.RouteKindOauth2Proxy, o.internalProxyURL),
			)
		}

		expanded = append(expanded,
			newRoute(vh, paths.CallbackPrefix, registry.RouteKindOauthCallback, o.ledgerURL),
		)
	}

	return expanded
}

// PrepareAuthRedirect mints a nonce bound to the client IP and target sub-domain, storing it
// with the proposed redirect, and returns a redirect to the auth domain's oauth2-proxy with
// the auth domain callback (carrying the nonce) as the rd parameter.
func (o *middlewareManager) PrepareAuthRedirect(
	proposedRedirect string, details requests.RequestDetails,
) (AuthRedirect, *errs.StatusError) {
	if details.ClientIP == "" {
		return AuthRedirect{}, errs.NewInternalErr(
			errors.New("client IP unavailable for nonce binding"),
			"Failed to prepare authentication",
		)
	}

	scheme := requestScheme(details)

	ctx, cancel := context.WithTimeout(context.Background(), mintTimeout)
	defer cancel()

	flow, err := o.ledger.Mint(ctx, ledger.MintRequest{
		ClientIP:        details.ClientIP,
		TargetScheme:    scheme,
		TargetSubdomain: details.Host,
		TargetURL:       proposedRedirect,
	})
	if err != nil {
		o.ll.Errorf("failed to mint nonce: %s", err)
		return AuthRedirect{}, errs.NewInternalErr(err, "Failed to prepare authentication")
	}

	o.ll.Infof("minted nonce for OAuth flow (client_ip=%s, target=%s)", details.ClientIP, proposedRedirect)

	callbackURL := fmt.Sprintf(
		"%s://%s%s?nonce=%s",
		scheme,
		o.userAuthURL,
		paths.CallbackPrefix,
		url.QueryEscape(flow.Nonce),
	)

	redirectURL := fmt.Sprintf(
		"%s://%s%s?rd=%s",
		scheme,
		o.userAuthURL,
		paths.Oauth2ProxyMiddlewareStartPath,
		url.QueryEscape(callbackURL),
	)

	cookie, err := cookies.NewResponse(oauthapi.BindingCookieName(flow.Nonce), flow.BindingSecret, cookies.Options{
		Path:   paths.CallbackPrefix,
		MaxAge: o.nonceTTL,
		Scheme: scheme,
	})
	if err != nil {
		o.ll.Errorf("failed to create binding cookie: %s", err)
		return AuthRedirect{}, errs.NewInternalErr(err, "Failed to prepare authentication")
	}

	return AuthRedirect{URL: redirectURL, SetCookie: cookie}, nil
}

// ValidateCookies extracts the sub-domain scoped cookie issued by the callback, identified
// by name, from the request's Cookie header. With the cookie session store the callback splits
// large sessions into chunks, which are joined. The cookie carries the oauth2-proxy session
// captured at the auth domain, which is resolved to its access_token through oauth2-proxy.
// Result.CookieHeader has the cookie (and any chunks) stripped.
func (o *middlewareManager) ValidateCookies(
	ctx context.Context, details requests.RequestDetails,
) (Result, *errs.StatusError) {
	result, sErr := o.proxy.Resolve(ctx, details, o.cookieName, o.sessionStore)
	return Result{AccessToken: result.AccessToken, CookieHeader: result.CookieHeader}, sErr
}
