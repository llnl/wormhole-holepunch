package oauthmngr

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/ctls/errs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
	"github.com/llnl/wormhole-holepunch/internal/ctls/streams"
	"github.com/llnl/wormhole-holepunch/internal/wormhole"
)

// oauth2ProxyMiddlewareManager implements the Validator interface for the middleware strategy.
// This strategy uses a single oauth2-proxy instance as the redirect target with Holepunch
// managing the multi-step flow to capture session cookies and issue subdomain-scoped cookies.
type oauth2ProxyMiddlewareManager struct {
	ll               logs.Logger
	kvStore          streams.KVStore
	cookieMaxAge     int
	cookieName       string
	internalProxyURL string
	nonceTTL         int
	proxyCookieName  string
	userAuthURL      string
}

func newOauth2ProxyMiddlewareManager(
	kvStore streams.KVStore,
	ll logs.Logger,
	oauthArgs args.OauthManagement,
) (*oauth2ProxyMiddlewareManager, error) {
	if oauthArgs.InternalProxyURL == "" {
		return nil, errors.New("internal URL is required for middleware strategy")
	}

	if oauthArgs.UserAuthURL == "" {
		return nil, errors.New("user auth URL is required for middleware strategy")
	}

	return &oauth2ProxyMiddlewareManager{
		ll:               ll,
		kvStore:          kvStore,
		internalProxyURL: oauthArgs.InternalProxyURL,
		cookieMaxAge:     oauthArgs.CookieMaxAge,
		cookieName:       oauthArgs.CookieName,
		nonceTTL:         oauthArgs.NonceTTL,
		proxyCookieName:  oauthArgs.ProxyCookieName,
		userAuthURL:      oauthArgs.UserAuthURL,
	}, nil
}

//

// ExpandSources adds the oauth2-proxy routes and the oauthmngr callback routes to raw sources.
// For middleware strategy, we need:
// 1. Routes to oauth2-proxy on the auth domain (/-/wormhole/oauth2)
// 2. Routes to our callback handler on all domains (/-/wormhole/oauthmngr)
func (o *oauth2ProxyMiddlewareManager) ExpandSources(rawSources []wormhole.RawSource) []wormhole.RawSource {
	expanded := make([]wormhole.RawSource, 0, len(rawSources))
	authDomainRoutes := make(map[string]bool)
	callbackRoutes := make(map[string]bool)

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

		if host == o.userAuthURL {
			routeKey := fmt.Sprintf("%s://%s", scheme, host)
			if !authDomainRoutes[routeKey] {
				authDomainRoutes[routeKey] = true

				oauth2Source := wormhole.RawSource{
					ID:          src.ID + "-oauth2-proxy",
					Source:      keys.NewURLString(fmt.Sprintf("%s://%s/-/wormhole%s", scheme, host, oauth2ProxyBasePath)),
					Destination: keys.NewURLString(o.internalProxyURL + oauth2ProxyBasePath),
					CommunityID: src.CommunityID,
				}
				expanded = append(expanded, oauth2Source)
			}
		}

		callbackKey := fmt.Sprintf("%s://%s", scheme, host)
		if !callbackRoutes[callbackKey] {
			callbackRoutes[callbackKey] = true

			callbackSource := wormhole.RawSource{
				ID:          src.ID + "-oauth-callback",
				Source:      keys.NewURLString(fmt.Sprintf("%s://%s/-/wormhole%s", scheme, host, managerPath)),
				Destination: keys.NewURLString(fmt.Sprintf("%s://%s/-/wormhole%s", scheme, host, managerPath)),
				CommunityID: src.CommunityID,
			}
			expanded = append(expanded, callbackSource)
		}
	}

	return expanded
}

// EstablishPreAuthentication returns a function that handles pre-auth logic for OAuth flows.
// It allows requests to oauth2-proxy endpoints and our callback handler to skip Holepunch auth.
func (o *oauth2ProxyMiddlewareManager) EstablishPreAuthentication(
	source wormhole.RawSource,
) func(requests.RequestDetails) (bool, *errs.StatusError) {
	return func(details requests.RequestDetails) (bool, *errs.StatusError) {
		if strings.HasPrefix(details.Path, "/-/wormhole"+oauth2ProxyBasePath) {
			if details.Host == o.userAuthURL {
				return true, nil
			}

			return false, errs.NewAuthErr(
				errors.New("oauth2-proxy endpoints only available on auth domain"),
				"Authentication service not available on this domain",
			)
		}

		if strings.HasPrefix(details.Path, "/-/wormhole"+managerPath) {
			return true, nil
		}

		return false, nil
	}
}

// EstablishPostAuthentication returns a function that processes the /-/wormhole/oauthmngr
// callback. At the auth domain: captures the oauth2-proxy session cookie, stores it against
// the nonce, and redirects to the target subdomain. At the target subdomain: retrieves that
// session data, validates the nonce binding, and issues a subdomain-scoped cookie.
func (o *oauth2ProxyMiddlewareManager) EstablishPostAuthentication(
	source wormhole.RawSource,
) func(context.Context, requests.RequestDetails) *errs.StatusError {
	return func(ctx context.Context, details requests.RequestDetails) *errs.StatusError {
		nonceParam := ""
		if idx := strings.Index(details.Path, "?nonce="); idx != -1 {
			nonceParam = details.Path[idx+7:]
			if idx := strings.Index(nonceParam, "&"); idx != -1 {
				nonceParam = nonceParam[:idx]
			}
		}

		if nonceParam == "" {
			o.ll.Warn("post-auth callback called without nonce parameter")
			return errs.NewBadReqErr(errors.New("missing nonce parameter"), "Invalid authentication request")
		}

		nonce, err := url.QueryUnescape(nonceParam)
		if err != nil {
			o.ll.Warnf("failed to decode nonce: %s", err)
			return errs.NewBadReqErr(err, "Invalid nonce format")
		}

		if details.Host == o.userAuthURL {
			return o.handleAuthDomainCallback(ctx, nonce, details)
		}

		return o.handleSubdomainCallback(ctx, nonce, details)
	}
}

// PrepareAuthRedirect creates the redirect URL to initiate the OAuth flow.
// It generates a nonce, stores it with the target URL and request binding, and returns
// a redirect to the auth domain's oauth2-proxy with the callback URL containing the nonce.
func (o *oauth2ProxyMiddlewareManager) PrepareAuthRedirect(
	proposedRedirect string, details requests.RequestDetails,
) (string, *errs.StatusError) {
	nonce, err := generateNonce()
	if err != nil {
		o.ll.Errorf("failed to generate nonce: %s", err)
		return "", errs.NewInternalErr(err, "Failed to prepare authentication")
	}

	scheme := details.Scheme
	if scheme == "" {
		scheme = "https"
	}

	data := nonceData{
		TargetURL:       proposedRedirect,
		ClientIP:        details.ClientIP,
		TargetSubdomain: details.Host,
		CreatedAt:       time.Now(),
		Used:            false,
	}

	ctx := context.Background()
	if err := storeNonce(ctx, o.kvStore, nonce, data); err != nil {
		o.ll.Errorf("failed to store nonce: %s", err)
		return "", errs.NewInternalErr(err, "Failed to prepare authentication")
	}

	o.ll.Infof("generated nonce for OAuth flow (client_ip=%s, target=%s)",
		details.ClientIP, proposedRedirect)

	callbackURL := fmt.Sprintf(
		"%s://%s/-/wormhole%s?nonce=%s",
		scheme,
		o.userAuthURL,
		managerPath,
		url.QueryEscape(nonce),
	)

	redirectURL := fmt.Sprintf(
		"%s://%s/-/wormhole%s/start?rd=%s",
		scheme,
		o.userAuthURL,
		oauth2ProxyBasePath,
		url.QueryEscape(callbackURL),
	)

	return redirectURL, nil
}

// ValidateCookies extracts the subdomain-scoped cookie issued by Holepunch, identified by
// name, from the request's Cookie header. Middleware mode issues its own cookie rather than
// relying on oauth2-proxy's directly. Result.CookieHeader has that cookie stripped.
func (o *oauth2ProxyMiddlewareManager) ValidateCookies(
	ctx context.Context, details requests.RequestDetails,
) (Result, *errs.StatusError) {
	cookieHeader := details.Headers[keys.CookieHeader]

	sessionCookieValue := extractCookie(cookieHeader, o.cookieName)
	if sessionCookieValue == "" {
		return Result{}, errs.SimpleAuthErr(errors.New("session cookie not found"))
	}

	return Result{
		AccessToken:  sessionCookieValue,
		CookieHeader: removeCookie(cookieHeader, o.cookieName),
	}, nil
}

// NewAuthRedirectErr builds a redirect error back through the nonce-bound auth-domain flow,
// targeting the request's own URL via PrepareAuthRedirect.
func (o *oauth2ProxyMiddlewareManager) NewAuthRedirectErr(
	details requests.RequestDetails,
) *errs.StatusError {
	redirectURL, sErr := o.PrepareAuthRedirect(targetURLFromDetails(details), details)
	if sErr != nil {
		return sErr
	}

	return errs.NewRedirectErr(redirectURL)
}

//

// handleAuthDomainCallback processes the callback at the auth domain.
// It captures the oauth2-proxy session cookie and stores it with the nonce.
func (o *oauth2ProxyMiddlewareManager) handleAuthDomainCallback(
	ctx context.Context, nonce string, details requests.RequestDetails,
) *errs.StatusError {
	storedNonce, err := retrieveAndConsumeNonce(ctx, o.kvStore, o.ll, nonce, o.nonceTTL)
	if err != nil {
		return errs.NewAuthErr(err, "Invalid or expired authentication session")
	}

	// Extract only the specific oauth2-proxy session cookie
	cookieHeader := details.Headers[keys.CookieHeader]

	sessionCookieValue := extractCookie(cookieHeader, o.proxyCookieName)
	if sessionCookieValue == "" {
		o.ll.Warnf("oauth2-proxy session cookie not found at auth domain (expected cookie name: %s)", o.proxyCookieName)
		cleanupNonce(ctx, o.kvStore, nonce)

		return errs.NewAuthErr(errors.New("session cookie not found"), "Authentication failed")
	}

	sessData := sessionData{
		SessionCookie: sessionCookieValue,
		NonceData:     storedNonce,
		CreatedAt:     time.Now(),
	}

	if err := storeSessionData(ctx, o.kvStore, nonce, sessData); err != nil {
		o.ll.Errorf("failed to store session data: %s", err)
		cleanupNonce(ctx, o.kvStore, nonce)

		return errs.NewInternalErr(errors.New("failed to store session data"), "Failed to process authentication")
	}

	o.ll.Info("captured session cookie at auth domain")

	scheme := details.Scheme
	if scheme == "" {
		scheme = "https"
	}

	redirectURL := fmt.Sprintf(
		"%s://%s/-/wormhole%s?nonce=%s",
		scheme,
		storedNonce.TargetSubdomain,
		managerPath,
		url.QueryEscape(nonce),
	)

	return errs.NewRedirectErr(redirectURL)
}

// handleSubdomainCallback processes the callback at the target subdomain.
// It retrieves the session data, validates bindings, and issues a subdomain-scoped cookie.
func (o *oauth2ProxyMiddlewareManager) handleSubdomainCallback(
	ctx context.Context, nonce string, details requests.RequestDetails,
) *errs.StatusError {
	sessData, err := retrieveAndDeleteSessionData(ctx, o.kvStore, o.ll, nonce, o.nonceTTL)
	if err != nil {
		return errs.NewAuthErr(err, "Invalid or expired authentication session")
	}

	if err := validateNonceBinding(o.ll, sessData.NonceData, details); err != nil {
		o.ll.Errorf("nonce binding validation failed: %s", err)
		return errs.NewAuthErr(err, "Authentication validation failed")
	}

	o.ll.Infof("validated nonce binding for subdomain callback (subdomain=%s)", details.Host)

	cookie := &http.Cookie{ //nolint:gosec // Secure is intentionally conditional on the request scheme
		Name:     o.cookieName,
		Value:    sessData.SessionCookie,
		Path:     "/",
		Domain:   details.Host,
		MaxAge:   o.cookieMaxAge,
		Secure:   details.Scheme == "https",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}

	o.ll.Infof("issuing subdomain-scoped cookie (subdomain=%s, max_age=%d)",
		details.Host, o.cookieMaxAge)

	return errs.NewRedirectErr(sessData.NonceData.TargetURL, errs.WithSetCookie(cookie))
}
