package oauthmngr

import (
	"context"
	"errors"
	"net/http"

	"github.com/llnl/wormhole-holepunch/internal/ctls/errs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
	"github.com/llnl/wormhole-holepunch/internal/wormhole"
)

var errOAuthNotConfigured = errors.New("oauth2 flow is not configured")

// noneManager is a no-op implementation of the Validator interface. It is used when no OAuth2
// flow is configured and will ensure that errors are returned for any attempts to use
// OAuth2 features.
type noneManager struct{}

func newNoneManager() Validator {
	return &noneManager{}
}

//

// ExpandSources returns the sources unchanged as no OAuth routes are needed.
func (*noneManager) ExpandSources(rawSources []wormhole.RawSource) []wormhole.RawSource {
	return rawSources
}

// EstablishPreAuthFunc returns a function that always returns false (don't skip auth)
// and no error, as OAuth is not configured.
func (*noneManager) EstablishPreAuthFunc(
	source wormhole.RawSource,
) func(requests.RequestDetails) (bool, *errs.StatusError) {
	return func(details requests.RequestDetails) (bool, *errs.StatusError) {
		return false, nil
	}
}

// PrepareAuthRedirect returns an error since OAuth is not configured.
func (*noneManager) PrepareAuthRedirect(
	_ string,
	_ requests.RequestDetails,
) (string, *errs.StatusError) {
	return "", errs.SimpleInternalErr(errOAuthNotConfigured)
}

// RedirectHandler returns an error since OAuth is not configured.
func (*noneManager) RedirectHandler(
	_ context.Context,
	_ requests.RequestDetails,
) (*http.Cookie, *errs.StatusError) {
	return nil, errs.SimpleInternalErr(errOAuthNotConfigured)
}

// ValidateCookies returns an error since OAuth is not configured. The Cookie header is
// passed through unchanged in Result.CookieHeader, since there's no Holepunch-owned
// cookie to strip.
func (*noneManager) ValidateCookies(
	_ context.Context,
	details requests.RequestDetails,
) (Result, *errs.StatusError) {
	return Result{CookieHeader: details.Headers[keys.CookieHeader]}, errs.SimpleAuthErr(errOAuthNotConfigured)
}
