package oauthmngr

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/ctls/errs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/paths"
	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr/oauthapi"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr/proxyauth"
	"github.com/llnl/wormhole-holepunch/internal/wormhole/registry"
)

// reverseManager implements the Validator interface for the reverse proxy strategy, where
// oauth2-proxy (reverse_proxy=true) establishes its session cookie on each sub-domain.
type reverseManager struct {
	proxy             proxyauth.Resolver
	proxyCookieName   string
	proxySessionStore oauthapi.SessionStore
	internalProxyURL  string
}

func newReverseManager(
	client requests.Client,
	ll logs.Logger,
	oauthArgs args.OauthManagement,
) (*reverseManager, error) {
	if oauthArgs.InternalProxyURL == "" {
		return nil, errors.New("oauth2-proxy internal URL is required for reverse strategy")
	}

	store, err := proxyauth.ParseSessionStore(oauthArgs.ProxySessionStore)
	if err != nil {
		return nil, err
	}

	return &reverseManager{
		proxy:             proxyauth.New(client, ll, oauthArgs.InternalProxyURL, oauthArgs.ProxyCookieName),
		proxyCookieName:   oauthArgs.ProxyCookieName,
		proxySessionStore: store,
		internalProxyURL:  oauthArgs.InternalProxyURL,
	}, nil
}

//

// ExpandSources adds, on every virtual host, an oauth2-proxy route forwarding
// /-/wormhole/oauth2 to the oauth2-proxy instance.
func (r *reverseManager) ExpandSources(rawSources []registry.RawSource) []registry.RawSource {
	expanded := append([]registry.RawSource{}, rawSources...)

	for _, vh := range virtualHosts(rawSources) {
		expanded = append(expanded,
			newRoute(vh, paths.Oauth2ProxyPrefix, registry.RouteKindOauth2Proxy, r.internalProxyURL),
		)
	}

	return expanded
}

// PrepareAuthRedirect creates a redirect URL to the sub-domain's oauth2-proxy start endpoint
// with the proposed redirect as the rd parameter. In reverse proxy mode, oauth2-proxy
// handles the entire OAuth flow and establishes cookies directly on the sub-domain.
func (r *reverseManager) PrepareAuthRedirect(
	proposedRedirect string, details requests.RequestDetails,
) (AuthRedirect, *errs.StatusError) {
	redirectURL := fmt.Sprintf(
		"%s://%s%s?rd=%s",
		requestScheme(details),
		details.Host,
		paths.Oauth2ProxyStartPath,
		url.QueryEscape(proposedRedirect),
	)

	return AuthRedirect{URL: redirectURL}, nil
}

// ValidateCookies extracts the oauth2-proxy session cookie, identified by the configured
// proxy cookie name, from the request's Cookie header; oauth2-proxy sets it directly on
// each sub-domain in reverse proxy mode. With the cookie session store, a session split by
// oauth2-proxy into chunks is joined. The session is then resolved to its access_token
// through oauth2-proxy. Result.CookieHeader has the cookie (and any chunks) stripped.
func (r *reverseManager) ValidateCookies(
	ctx context.Context, details requests.RequestDetails,
) (Result, *errs.StatusError) {
	result, sErr := r.proxy.Resolve(ctx, details, r.proxyCookieName, r.proxySessionStore)
	return Result{AccessToken: result.AccessToken, CookieHeader: result.CookieHeader}, sErr
}

func (r *reverseManager) RemoveSessionCookies(cookieHeader string) string {
	return oauthapi.RemoveCookie(cookieHeader, r.proxyCookieName)
}
