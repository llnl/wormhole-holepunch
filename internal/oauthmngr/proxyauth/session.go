package proxyauth

import (
	"context"
	"errors"
	"fmt"

	"github.com/llnl/wormhole-holepunch/internal/ctls/errs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr/oauthapi"
)

// Result contains the access token and the Cookie header with the owned session removed.
type Result struct {
	AccessToken  string
	CookieHeader string
}

// ParseSessionStore validates the configured oauth2-proxy session store, defaulting to
// cookie to match oauth2-proxy's own default.
func ParseSessionStore(raw string) (oauthapi.SessionStore, error) {
	if raw == "" {
		return oauthapi.SessionStoreCookie, nil
	}

	store := oauthapi.SessionStore(raw)
	if !store.Valid() {
		return "", fmt.Errorf(
			"invalid oauth2-proxy session store: %s (valid options: %s, %s)",
			raw,
			oauthapi.SessionStoreCookie,
			oauthapi.SessionStoreRedis,
		)
	}

	return store, nil
}

// Resolve reads the named browser cookie and resolves its session to an access token.
// The browser cookie name may differ from the cookie name expected by oauth2-proxy.
func (p Resolver) Resolve(
	ctx context.Context,
	details requests.RequestDetails,
	name string,
	store oauthapi.SessionStore,
) (Result, *errs.StatusError) {
	result, sErr := p.sessionFromCookies(details, name, store)
	if sErr != nil {
		return Result{}, sErr
	}

	token, sErr := p.accessToken(ctx, details, result.AccessToken)
	if sErr != nil {
		return Result{}, sErr
	}

	result.AccessToken = token

	return result, nil
}

//

// sessionFromCookies reads the named session cookie from the request's Cookie header,
// joining chunks where the session store permits them.
func (p Resolver) sessionFromCookies(
	details requests.RequestDetails,
	name string,
	store oauthapi.SessionStore,
) (Result, *errs.StatusError) {
	cookieHeader := details.Headers[keys.CookieHeader]

	value, err := oauthapi.JoinCookie(oauthapi.ParseCookies(cookieHeader), name, store)
	if err != nil {
		if !errors.Is(err, oauthapi.ErrCookieNotFound) {
			p.ll.Warnf("unusable session cookie %s (session_store=%s): %s", name, store, err)
		}

		return Result{}, errs.SimpleAuthErr(fmt.Errorf("session cookie %s: %w", name, err))
	}

	return Result{
		AccessToken:  value,
		CookieHeader: oauthapi.RemoveCookie(cookieHeader, name),
	}, nil
}
