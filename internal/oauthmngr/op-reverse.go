package oauthmngr

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/ctls/errs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
	"github.com/llnl/wormhole-holepunch/internal/wormhole"
)

// oauth2ProxyReverseManager implements the Validator interface for the reverse proxy strategy.
// In this strategy, oauth2-proxy is configured with reverse_proxy=true and exists behind Envoy.
// Holepunch ensures routes prefixed with /-/wormhole/oauth2 are correctly routed to oauth2-proxy,
// allowing it to establish session cookies for each individual subdomain.
type oauth2ProxyReverseManager struct {
	ll               logs.Logger
	proxyCookieName  string
	internalProxyURL string
}

func newOauth2ProxyReverseManager(ll logs.Logger, oauthArgs args.OauthManagement) (*oauth2ProxyReverseManager, error) {
	if oauthArgs.InternalProxyURL == "" {
		return nil, errors.New("oauth2-proxy upstream URL is required for reverse proxy strategy")
	}

	return &oauth2ProxyReverseManager{
		ll:               ll,
		proxyCookieName:  oauthArgs.ProxyCookieName,
		internalProxyURL: oauthArgs.InternalProxyURL,
	}, nil
}

//

// ExpandSources adds the oauth2-proxy routes to the raw sources. These routes are prefixed
// with /-/wormhole/oauth2 and will be routed to the oauth2-proxy upstream.
func (o *oauth2ProxyReverseManager) ExpandSources(rawSources []wormhole.RawSource) []wormhole.RawSource {
	expanded := make([]wormhole.RawSource, 0, len(rawSources))
	oauth2Routes := make(map[string]bool)

	for _, src := range rawSources {
		expanded = append(expanded, src)

		if src.Source.URL == nil {
			continue
		}

		host := src.Source.URL.Hostname()

		scheme := src.Source.URL.Scheme
		if scheme == "" {
			scheme = "https"
		}

		routeKey := fmt.Sprintf("%s://%s", scheme, host)
		if oauth2Routes[routeKey] {
			continue
		}

		oauth2Routes[routeKey] = true

		oauth2Source := wormhole.RawSource{
			ID:          src.ID + "-oauth2-proxy",
			Source:      newURLString(fmt.Sprintf("%s://%s/-/wormhole%s", scheme, host, oauth2ProxyBasePath)),
			Destination: newURLString(o.internalProxyURL + oauth2ProxyBasePath),
			CommunityID: src.CommunityID,
		}

		expanded = append(expanded, oauth2Source)
	}

	return expanded
}

// EstablishPreAuthFunc returns a function that checks if the request is for an oauth2-proxy
// endpoint. If so, it allows the request to skip Holepunch auth and be handled directly by
// oauth2-proxy upstream.
func (o *oauth2ProxyReverseManager) EstablishPreAuthFunc(
	source wormhole.RawSource,
) func(requests.RequestDetails) (bool, *errs.StatusError) {
	return func(details requests.RequestDetails) (bool, *errs.StatusError) {
		if strings.HasPrefix(details.Path, "/-/wormhole"+oauth2ProxyBasePath) {
			return true, nil
		}

		return false, nil
	}
}

// PrepareAuthRedirect creates a redirect URL to oauth2-proxy's /oauth2/start endpoint
// with the proposed redirect as the rd parameter. In reverse proxy mode, oauth2-proxy
// handles the entire OAuth flow and establishes cookies directly on the subdomain.
func (o *oauth2ProxyReverseManager) PrepareAuthRedirect(
	proposedRedirect string, details requests.RequestDetails,
) (string, *errs.StatusError) {
	scheme := details.Scheme
	if scheme == "" {
		scheme = "https"
	}

	redirectURL := fmt.Sprintf(
		"%s://%s/-/wormhole%s/start?rd=%s",
		scheme,
		details.Host,
		oauth2ProxyBasePath,
		url.QueryEscape(proposedRedirect),
	)

	return redirectURL, nil
}

// RedirectHandler is not used in the reverse proxy strategy since oauth2-proxy handles
// all callback logic directly. This method returns an error if called.
func (o *oauth2ProxyReverseManager) RedirectHandler(
	ctx context.Context, details requests.RequestDetails,
) (*http.Cookie, *errs.StatusError) {
	return nil, errs.NewInternalErr(
		errors.New("redirect handler not used in reverse proxy strategy"),
		"OAuth redirect handler is not applicable for this configuration",
	)
}

// ValidateCookies extracts the oauth2-proxy session cookie, identified by the configured
// proxy cookie name, from the request's Cookie header; oauth2-proxy sets it directly on
// each subdomain in reverse proxy mode. Result.CookieHeader has that cookie stripped.
func (o *oauth2ProxyReverseManager) ValidateCookies(
	ctx context.Context, details requests.RequestDetails,
) (Result, *errs.StatusError) {
	cookieHeader := details.Headers[keys.CookieHeader]

	sessionCookieValue := extractCookie(cookieHeader, o.proxyCookieName)
	if sessionCookieValue == "" {
		return Result{}, errs.SimpleAuthErr(errors.New("oauth2-proxy session cookie not found"))
	}

	return Result{
		AccessToken:  sessionCookieValue,
		CookieHeader: removeCookie(cookieHeader, o.proxyCookieName),
	}, nil
}
