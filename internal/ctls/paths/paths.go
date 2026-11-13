// Package paths defines the HTTP paths managed by Holepunch.
package paths

const (
	// ReservedPrefix is reserved on every virtual host for Holepunch's own use.
	ReservedPrefix = "/-/wormhole/"
	// Oauth2ProxyPrefix is the oauth2-proxy proxy_prefix, forwarded straight to oauth2-proxy.
	Oauth2ProxyPrefix = ReservedPrefix + "oauth2"
	// Oauth2ProxyMiddlewarePrefix is oauth2-proxy's standard proxy_prefix on the
	// dedicated middleware auth host.
	Oauth2ProxyMiddlewarePrefix = "/oauth2"
	// Oauth2ProxyAuthPath resolves sessions through oauth2-proxy.
	Oauth2ProxyAuthPath = Oauth2ProxyPrefix + "/auth"
	// Oauth2ProxyStartPath starts an OAuth flow through oauth2-proxy.
	Oauth2ProxyStartPath = Oauth2ProxyPrefix + "/start"
	// Oauth2ProxyMiddlewareStartPath starts an OAuth flow on the middleware auth host.
	Oauth2ProxyMiddlewareStartPath = Oauth2ProxyMiddlewarePrefix + "/start"
	// CallbackPrefix is the cookie hand-off callback, forwarded by Envoy to the oauthmngr
	// ledger service.
	CallbackPrefix = ReservedPrefix + "oauthmngr"

	// APIPrefix namespaces the admin API and shared service health/version endpoints.
	APIPrefix             = "/api/v1/"
	ControlsPath          = APIPrefix + "state/ctls"
	RoutesWebhookPath     = APIPrefix + "webhook/routes"
	InvalidateWebhookPath = APIPrefix + "webhook/invalidate"
	VersionPath           = APIPrefix + "version"
	HealthPath            = APIPrefix + "healthz"
)
