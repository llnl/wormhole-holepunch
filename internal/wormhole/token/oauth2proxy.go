package token

/*
import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/llnl/wormhole-holepunch/internal/ctls/errs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
)

const (
	authPath      = "/oauth2/auth"
	startPath     = "/oauth2/start"
	redirectParam = "rd"
)

type oauth2ProxyResult struct {
	// headers returned by oauth2-proxy (identity headers, etc.)
	headers map[string]string
}

// callProxyAuth calls oauth2-proxy's /oauth2/auth endpoint, forwarding cookies
// in order to allow this service to handle the initial authentication process.
func (i internal) callProxyAuth(
	ctx context.Context,
	details requests.RequestDetails,
	cookies []*http.Cookie,
) (oauth2ProxyResult, *errs.StatusError) {
	reqHeaders := map[string]string{
		// Useful if oauth2-proxy uses host-based rules.
		keys.XForwardHostHeader:  details.Host,
		keys.XForwardProtoHeader: details.Scheme,
		keys.XForwardURIHeader:   details.Path,
	}

	respHeaders, rErr := i.client.GetHeaders(
		ctx,
		i.oauth2AuthURL.String(),
		reqHeaders,
		cookies,
	)
	if rErr != nil {
		return oauth2ProxyResult{
			headers: respHeaders,
		}, errs.NewRedirectErr(i.constructProxyRedirect(details))
	}

	if respHeaders[keys.Oauth2ProxyAccessTokenHeader] == "" {
		msg := fmt.Sprintf(
			"access_token header %s not found, available headers (%s)",
			keys.Oauth2ProxyAccessTokenHeader,
			mapKeys(respHeaders),
		)

		i.ll.WarnCtx(ctx, msg)

		return oauth2ProxyResult{}, errs.SimpleInternalErr(errors.New(msg))
	}

	return oauth2ProxyResult{
		headers: respHeaders,
	}, nil
}

// constructProxyRedirect generates a valid login URL (along with associated
// final redirect) to begin a user on their oauth2 authentication flow. Errors
// have been formatted appropriately (e.g., redirects).
func (i internal) constructProxyRedirect(details requests.RequestDetails) string {
	// Build the redirect target as a proper URL.
	targetURL := (&url.URL{
		Scheme: details.Scheme,
		Host:   details.Host,
		Path:   details.Path,
	})
	target := targetURL.String()

	// Copy base redirect URL so we never mutate the stored one.
	u2 := *i.oauth2RedirectURL

	q := u2.Query()
	q.Set(redirectParam, target)
	u2.RawQuery = q.Encode()

	return u2.String()
}

//

func buildAuthURL(proxyURL string) *url.URL {
	u, _ := url.Parse(proxyURL)

	return u.JoinPath(authPath)
}

func buildRedirectURL(proxyURL string) *url.URL {
	u, _ := url.Parse(proxyURL)

	return u.JoinPath(startPath)
}

func mapKeys(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	return strings.Join(keys, ", ")
}
*/
