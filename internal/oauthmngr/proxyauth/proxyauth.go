// Package proxyauth resolves browser session cookies to access tokens through oauth2-proxy.
// oauth2-proxy remains responsible for validating sessions and managing token lifecycles.
package proxyauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/llnl/wormhole-holepunch/internal/ctls/cookies"
	"github.com/llnl/wormhole-holepunch/internal/ctls/errs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/paths"
	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
)

type Resolver struct {
	client     requests.Client
	ll         logs.Logger
	authURL    string
	cookieName string
}

func New(client requests.Client, ll logs.Logger, internalProxyURL, cookieName string) Resolver {
	return Resolver{
		client:     client,
		ll:         ll,
		authURL:    internalProxyURL + paths.Oauth2ProxyAuthPath,
		cookieName: cookieName,
	}
}

//

// accessToken resolves a session to an access token through oauth2-proxy.
func (p Resolver) accessToken(
	ctx context.Context,
	details requests.RequestDetails,
	session string,
) (string, *errs.StatusError) {
	scheme := details.Scheme
	if scheme == "" {
		scheme = "https"
	}

	headers := map[string]string{
		// Wormhole deployed oauth2-proxy uses host-based rules.
		keys.XForwardHostHeader:  details.Host,
		keys.XForwardProtoHeader: scheme,
		keys.XForwardURIHeader:   details.Path,
	}

	cookie, err := cookies.NewRequest(p.cookieName, session)
	if err != nil {
		return "", errs.SimpleInternalErr(fmt.Errorf("creating oauth2-proxy request cookie: %w", err))
	}

	respHeaders, rErr := p.client.GetHeaders(ctx, p.authURL, headers, []*http.Cookie{cookie})
	if rErr != nil {
		if rErr.StatusCode == http.StatusUnauthorized || rErr.StatusCode == http.StatusForbidden {
			return "", errs.SimpleAuthErr(fmt.Errorf("oauth2-proxy rejected session: %w", rErr))
		}

		return "", errs.SimpleInternalErr(fmt.Errorf("oauth2-proxy auth request failed: %w", rErr))
	}

	token := respHeaders[keys.Oauth2ProxyAccessTokenHeader]
	if token == "" {
		return "", errs.SimpleInternalErr(errors.New(
			"oauth2-proxy returned no access token, ensure pass_access_token and set_xauthrequest are enabled",
		))
	}

	return token, nil
}
