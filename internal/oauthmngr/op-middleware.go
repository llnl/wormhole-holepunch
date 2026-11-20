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
	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
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
	proxyCookieName  string
	internalProxyURL string
	ledgerURL        string
	nonceTTL         int
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

	if oauthapi.HTTPSOrigin(oauthArgs.UserAuthURL) == "" {
		return nil, errors.New("a valid auth HTTPS authority is required for middleware strategy")
	}

	if oauthArgs.OauthLedgerURL == "" {
		return nil, errors.New("ledger URL is required for middleware strategy")
	}

	if oauthArgs.NonceTTL <= 0 {
		return nil, errors.New("a positive nonce TTL is required for middleware strategy")
	}

	// The oauth2-proxy session store only shapes the auth-domain capture, but a mismatched
	// value is still rejected here so both components fail fast on the same configuration.
	if _, err := proxyauth.ParseSessionStore(oauthArgs.ProxySessionStore); err != nil {
		return nil, err
	}

	flowStore, err := ledger.New(
		kvStore,
		ll,
		oauthArgs.UserAuthURL,
		time.Duration(oauthArgs.NonceTTL)*time.Second,
		time.Duration(oauthArgs.CookieMaxAge)*time.Second,
	)
	if err != nil {
		return nil, err
	}

	return &middlewareManager{
		ll:               ll,
		ledger:           flowStore,
		proxy:            proxyauth.New(client, ll, oauthArgs.InternalProxyURL, oauthArgs.ProxyCookieName),
		cookieName:       oauthArgs.CookieName,
		proxyCookieName:  oauthArgs.ProxyCookieName,
		internalProxyURL: oauthArgs.InternalProxyURL,
		ledgerURL:        oauthArgs.OauthLedgerURL,
		nonceTTL:         oauthArgs.NonceTTL,
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

// PrepareAuthRedirect mints a nonce bound to the target sub-domain, storing it
// with the proposed redirect, and returns a redirect to the auth domain's oauth2-proxy with
// the auth domain callback (carrying the nonce) as the rd parameter.
func (o *middlewareManager) PrepareAuthRedirect(
	proposedRedirect string, details requests.RequestDetails,
) (AuthRedirect, *errs.StatusError) {
	scheme := requestScheme(details)
	if scheme != "https" || oauthapi.HTTPSOrigin(details.Host) == "" {
		err := errors.New("OAuth middleware handoff requires an HTTPS application origin")
		o.ll.Warn(err.Error())

		return AuthRedirect{}, errs.NewInternalErr(err, "Failed to prepare authentication")
	}

	ctx, cancel := context.WithTimeout(context.Background(), mintTimeout)
	defer cancel()

	flow, err := o.ledger.Mint(ctx, ledger.MintRequest{
		TargetScheme:    scheme,
		TargetSubdomain: details.Host,
		TargetURL:       proposedRedirect,
	})
	if err != nil {
		o.ll.Errorf("failed to mint nonce: %s", err)
		return AuthRedirect{}, errs.NewInternalErr(err, "Failed to prepare authentication")
	}

	o.ll.Infof("minted nonce for OAuth flow (target=%s)", oauthapi.LogSafeURL(proposedRedirect))

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
		Path:   "/",
		MaxAge: o.nonceTTL,
		Scheme: scheme,
	})
	if err != nil {
		o.ll.Errorf("failed to create binding cookie: %s", err)
		return AuthRedirect{}, errs.NewInternalErr(err, "Failed to prepare authentication")
	}

	return AuthRedirect{URL: redirectURL, SetCookie: cookie}, nil
}

// ValidateCookies reads the host session handle issued by the callback from the request's
// Cookie header and resolves it through the ledger. A handle only resolves on the host it was
// issued for, so a session from one application can't be replayed against another. The
// oauth2-proxy session behind it is then resolved to its access_token through oauth2-proxy.
// Result.CookieHeader has both the application session and oauth2-proxy cookies
// (and any chunks) stripped.
func (o *middlewareManager) ValidateCookies(
	ctx context.Context, details requests.RequestDetails,
) (Result, *errs.StatusError) {
	handle, ok := oauthapi.ParseCookies(details.Headers[keys.CookieHeader])[o.cookieName]
	if !ok || handle == "" {
		return Result{}, errs.SimpleAuthErr(fmt.Errorf("session cookie %s: %w", o.cookieName, oauthapi.ErrCookieNotFound))
	}

	proxySession, err := o.ledger.ResolveHostSession(ctx, handle, details.Host)

	switch {
	case errors.Is(err, ledger.ErrSessionUnavailable), errors.Is(err, ledger.ErrBindingMismatch):
		return Result{}, errs.SimpleAuthErr(fmt.Errorf("session cookie %s: %w", o.cookieName, err))
	case err != nil:
		o.ll.Errorf("unable to resolve oauth host session: %s", err)
		return Result{}, errs.SimpleInternalErr(err)
	}

	token, sErr := o.proxy.AccessToken(ctx, details, proxySession)
	if sErr != nil {
		return Result{}, sErr
	}

	return Result{
		AccessToken:  token,
		CookieHeader: o.RemoveSessionCookies(details.Headers[keys.CookieHeader]),
	}, nil
}

func (o *middlewareManager) RemoveSessionCookies(cookieHeader string) string {
	stripped := oauthapi.RemoveCookie(oauthapi.RemoveCookie(cookieHeader, o.cookieName), o.proxyCookieName)

	return oauthapi.RemoveFlowCookies(stripped)
}
