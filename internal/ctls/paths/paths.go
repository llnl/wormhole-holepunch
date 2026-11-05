// Package paths defines the HTTP paths managed by Holepunch.
package paths

const (
	// ReservedPrefix is reserved on every virtual host for Holepunch's own use.
	ReservedPrefix = "/-/wormhole/"
	// Oauth2ProxyPrefix is the oauth2-proxy proxy_prefix, forwarded straight to oauth2-proxy.
	Oauth2ProxyPrefix = ReservedPrefix + "oauth2"
	// Oauth2ProxyAuthPath resolves sessions through oauth2-proxy.
	Oauth2ProxyAuthPath = Oauth2ProxyPrefix + "/auth"
	// Oauth2ProxyStartPath starts an OAuth flow through oauth2-proxy.
	Oauth2ProxyStartPath = Oauth2ProxyPrefix + "/start"
	// CallbackPrefix is the cookie hand-off callback handled by the oauthmngr wasm plugin.
	CallbackPrefix = ReservedPrefix + "oauthmngr"

	// CapturePath and RedeemPath are the Ledger endpoints, each accepting a JSON encoded
	// request via POST. Responses are:
	//   - 200: JSON encoded response.
	//   - 400: malformed request.
	//   - 403: the flow is unavailable or the binding did not match.
	//   - 5xx: any other failure.
	CapturePath = "/v1/oauthmngr/capture"
	RedeemPath  = "/v1/oauthmngr/redeem"

	// APIPrefix namespaces the admin API and shared service health/version endpoints.
	APIPrefix             = "/api/v1/"
	ControlsPath          = APIPrefix + "state/ctls"
	RoutesWebhookPath     = APIPrefix + "webhook/routes"
	InvalidateWebhookPath = APIPrefix + "webhook/invalidate"
	VersionPath           = APIPrefix + "version"
	HealthPath            = APIPrefix + "healthz"
)
