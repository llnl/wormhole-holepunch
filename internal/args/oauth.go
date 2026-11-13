package args

import (
	"github.com/urfave/cli/v3"
)

const (
	categoryOauth                 = "OAuth Management"
	oauthProxyName                = "oauth-internal-proxy" //nolint:gosec
	oauthStrategyName             = "oauth-strategy"
	oauthCookieMaxAgeName         = "oauth-cookie-max-age"
	oauthCookieNameName           = "oauth-cookie-name"
	oauthProxyCookieNameName      = "oauth-proxy-cookie-name"
	oauthUserAuthURLName          = "oauth-user-auth-url"
	oauthNonceTTLName             = "oauth-nonce-ttl"
	oauthProxySessionStore        = "oauth-proxy-session-store"
	oauthLedgerURLName            = "oauth-ledger-url"
	oauthDisableClientIPCheckName = "oauth-disable-client-ip-check"
)

type OauthManagement struct {
	// CookieMaxAge is the lifetime in seconds of the host-only session cookie
	// issued by the middleware strategy (default: 12 hours).
	CookieMaxAge int
	// CookieName is the name of the host-only session cookie issued by Holepunch
	// after the middleware handoff.
	CookieName string
	// NonceTTL is the lifetime in seconds of middleware-flow nonces
	// (default: 5 minutes).
	NonceTTL int
	// DisableClientIPCheck disables binding middleware OAuth flows to the
	// initiating client's IP address. Host and browser-secret checks remain enabled.
	DisableClientIPCheck bool
	// InternalProxyURL is the URL Holepunch uses to reach the oauth2-proxy
	// service (e.g., http://oauth2-proxy.svc.cluster.local:4180).
	InternalProxyURL string
	// ProxyCookieName is the name of the oauth2-proxy session cookie. The
	// middleware strategy captures it on the auth host; the reverse strategy
	// reads it on each application host.
	ProxyCookieName string
	// ProxySessionStore must match oauth2-proxy's session_store_type (cookie or
	// redis). Cookie sessions may be split into numbered chunks.
	ProxySessionStore string
	// OauthLedgerURL is the URL of the oauthmngr session Ledger, Envoy forwards the OAuth
	// callback route to it. Required for the oauth2-proxy-middleware strategy.
	OauthLedgerURL string
	// Strategy selects how OAuth sessions are handled: none,
	// oauth2-proxy-reverse, or oauth2-proxy-middleware (default: none).
	Strategy string
	// UserAuthURL is the shared auth host for middleware redirects, as a
	// hostname with an optional port and no scheme (e.g., auth.example.com).
	UserAuthURL string
}

func (f *FlagBuilder) OauthManagementFlags(om *OauthManagement) *FlagBuilder {
	f.Flags = append(f.Flags, []cli.Flag{
		&cli.IntFlag{
			Category:    categoryOauth,
			Destination: &om.CookieMaxAge,
			Name:        oauthCookieMaxAgeName,
			Sources:     envWrapper("OAUTH_COOKIE_MAX_AGE"),
			Usage:       "Middleware session cookie lifetime in seconds",
			Value:       43200,
		},
		&cli.StringFlag{
			Category:    categoryOauth,
			Destination: &om.CookieName,
			Name:        oauthCookieNameName,
			Sources:     envWrapper("OAUTH_COOKIE_NAME"),
			Usage:       "Name of the middleware host-only session cookie issued by Holepunch",
			Value:       "_wormhole_session",
		},
		&cli.StringFlag{
			Action:      validateURLAction,
			Destination: &om.InternalProxyURL,
			Category:    categoryOauth,
			Sources:     envWrapper("OAUTH2_PROXY_INTERNAL"),
			Name:        oauthProxyName,
			Usage:       "URL Holepunch uses to reach oauth2-proxy (e.g., http://proxy.namespace.svc.cluster.local:4180)",
		},
		&cli.IntFlag{
			Category:    categoryOauth,
			Destination: &om.NonceTTL,
			Name:        oauthNonceTTLName,
			Sources:     envWrapper("OAUTH_NONCE_TTL"),
			Usage:       "Lifetime in seconds of middleware-flow nonces",
			Value:       300,
		},
		&cli.BoolFlag{
			Category:    categoryOauth,
			Destination: &om.DisableClientIPCheck,
			Name:        oauthDisableClientIPCheckName,
			Sources:     envWrapper("OAUTH_DISABLE_CLIENT_IP_CHECK"),
			Usage:       "Disable client IP binding for middleware OAuth flows",
		},
		&cli.StringFlag{
			Action:      validateURLAction,
			Category:    categoryOauth,
			Destination: &om.OauthLedgerURL,
			Name:        oauthLedgerURLName,
			Sources:     envWrapper("OAUTH_LEDGER_URL"),
			Usage:       "URL Envoy uses to reach the oauthmngr session ledger (oauth2-proxy-middleware strategy)",
		},
		&cli.StringFlag{
			Category:    categoryOauth,
			Destination: &om.ProxyCookieName,
			Name:        oauthProxyCookieNameName,
			Sources:     envWrapper("OAUTH_PROXY_COOKIE_NAME"),
			Usage:       "Name of the oauth2-proxy session cookie",
			Value:       "_oauth2_proxy",
		},
		&cli.StringFlag{
			Category:    categoryOauth,
			Destination: &om.ProxySessionStore,
			Name:        oauthProxySessionStore,
			Sources:     envWrapper("OAUTH_PROXY_SESSION_STORE"),
			Usage:       "oauth2-proxy session_store_type: cookie or redis",
			Value:       "cookie",
		},
		&cli.StringFlag{
			Category:    categoryOauth,
			Destination: &om.Strategy,
			Name:        oauthStrategyName,
			Sources:     envWrapper("OAUTH_STRATEGY"),
			Usage:       "OAuth session strategy: none, oauth2-proxy-reverse, or oauth2-proxy-middleware",
			Value:       "none",
		},
		&cli.StringFlag{
			Category:    categoryOauth,
			Destination: &om.UserAuthURL,
			Name:        oauthUserAuthURLName,
			Sources:     envWrapper("OAUTH_USER_AUTH_URL"),
			Usage:       "Shared auth host for middleware redirects (hostname[:port], without scheme)",
		},
	}...)

	return f
}
