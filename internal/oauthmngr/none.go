package oauthmngr

import (
	"context"
	"errors"

	"github.com/llnl/wormhole-holepunch/internal/ctls/errs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
	"github.com/llnl/wormhole-holepunch/internal/wormhole/registry"
)

var errOAuthNotConfigured = errors.New("oauth2 flow is not configured")

// noneManager is a no-op implementation of the Validator interface. It is used when no OAuth2
// flow is configured and will ensure that errors are returned for any attempts to use
// OAuth2 features.
type noneManager struct{}

func (*noneManager) RemoveSessionCookies(cookieHeader string) string {
	return cookieHeader
}

func newNoneManager() Validator {
	return &noneManager{}
}

//

// ExpandSources returns a copy of the sources without adding OAuth routes.
func (*noneManager) ExpandSources(rawSources []registry.RawSource) []registry.RawSource {
	return append([]registry.RawSource{}, rawSources...)
}

// PrepareAuthRedirect returns an error since OAuth is not configured.
func (*noneManager) PrepareAuthRedirect(
	_ string,
	_ requests.RequestDetails,
) (AuthRedirect, *errs.StatusError) {
	return AuthRedirect{}, errs.SimpleInternalErr(errOAuthNotConfigured)
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
