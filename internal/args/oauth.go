package args

import (
	"github.com/urfave/cli/v3"
)

const (
	categoryOauth            = "Oauth Management"
	oauthProxyName           = "oauth-internal-proxy" //nolint:gosec
	oauthStrategyName        = "oauth-strategy"
	oauthCookieMaxAgeName    = "oauth-cookie-max-age"
	oauthCookieNameName      = "oauth-cookie-name"
	oauthProxyCookieNameName = "oauth-proxy-cookie-name"
	oauthUserAuthURLName     = "oauth-user-auth-url"
	oauthNonceTTLName        = "oauth-nonce-ttl"
)

type OauthManagement struct {
	// CookieMaxAge is the maximum age in seconds for subdomain-scoped cookies
	// issued by Holepunch (default: 12 hours = 43200 seconds).
	CookieMaxAge int
	// CookieName is the name of the cookie used to store the session token issued by Holepunch.
	CookieName string
	// NonceTTL is the time-to-live in seconds for nonces used in OAuth flow (default: 5 minutes = 300 seconds).
	NonceTTL int
	// InternalProxyURL is the target URL for interactions with the oauth2-proxy service driven by
	// Holepunch. This is typically the internal service URL for the oauth2-proxy service
	// (e.g., http://oauth2-proxy.svc.cluster.local:4180).
	InternalProxyURL string
	// ProxyCookieName is the name of the oauth2-proxy session cookie to capture from the auth domain.
	ProxyCookieName string
	// Strategy is the strategy used for oauth2 code flow. This is used to
	// determine which implementation is used to handle the flow.
	Strategy string
	// UserAuthURL is the user facing URL (e.g., auth.example.com) used when constructing
	// the redirect URL for the oauth2-proxy service.
	UserAuthURL string
}

func (f *FlagBuilder) OauthManagementFlags(om *OauthManagement) *FlagBuilder {
	f.Flags = append(f.Flags, []cli.Flag{
		&cli.IntFlag{
			Category:    categoryOauth,
			Destination: &om.CookieMaxAge,
			Name:        oauthCookieMaxAgeName,
			Sources:     envWrapper("OAUTH_COOKIE_MAX_AGE"),
			Usage:       "Max age in seconds for subdomain-scoped cookies (default: 43200 = 12 hours)",
			Value:       43200,
		},
		&cli.StringFlag{
			Category:    categoryOauth,
			Destination: &om.CookieName,
			Name:        oauthCookieNameName,
			Sources:     envWrapper("OAUTH_COOKIE_NAME"),
			Usage:       "Name of the session cookie issued by Holepunch to target subdomains",
			Value:       "_wormhole_session",
		},
		&cli.StringFlag{
			Action:      validateURLAction,
			Destination: &om.InternalProxyURL,
			Category:    categoryOauth,
			Sources:     envWrapper("OAUTH2_PROXY_INTERNAL"),
			Name:        oauthProxyName,
			Usage:       "Internal proxy URL for oauth2-proxy service (e.g., http://proxy.namespace.svc.cluster.local:4180)",
		},
		&cli.IntFlag{
			Category:    categoryOauth,
			Destination: &om.NonceTTL,
			Name:        oauthNonceTTLName,
			Sources:     envWrapper("OAUTH_NONCE_TTL"),
			Usage:       "TTL in seconds for OAuth nonces (default: 300 = 5 minutes)",
			Value:       300,
		},
		&cli.StringFlag{
			Category:    categoryOauth,
			Destination: &om.ProxyCookieName,
			Name:        oauthProxyCookieNameName,
			Sources:     envWrapper("OAUTH_PROXY_COOKIE_NAME"),
			Usage:       "Name of the oauth2-proxy session cookie to capture from auth domain",
			Value:       "_oauth2_proxy",
		},
		&cli.StringFlag{
			Category:    categoryOauth,
			Destination: &om.Strategy,
			Name:        oauthStrategyName,
			Sources:     envWrapper("OAUTH_STRATEGY"),
			Usage:       "Strategy used for OAuth flow (oauth2-proxy-middleware, oauth2-proxy-reverse, none)",
			Value:       "none",
		},
		&cli.StringFlag{
			Category:    categoryOauth,
			Destination: &om.UserAuthURL,
			Name:        oauthUserAuthURLName,
			Sources:     envWrapper("OAUTH_USER_AUTH_URL"),
			Usage:       "User facing URL for OAuth flow (oauth2-proxy-middleware strategy, e.g., auth.example.com)",
		},
	}...)

	return f
}
