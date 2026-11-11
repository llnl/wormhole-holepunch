package paths

import "testing"

func TestPaths(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{"reserved prefix", ReservedPrefix, "/-/wormhole/"},
		{"oauth2 proxy prefix", Oauth2ProxyPrefix, "/-/wormhole/oauth2"},
		{"middleware oauth2 proxy prefix", Oauth2ProxyMiddlewarePrefix, "/oauth2"},
		{"oauth2 proxy auth", Oauth2ProxyAuthPath, "/-/wormhole/oauth2/auth"},
		{"oauth2 proxy start", Oauth2ProxyStartPath, "/-/wormhole/oauth2/start"},
		{"middleware oauth2 proxy start", Oauth2ProxyMiddlewareStartPath, "/oauth2/start"},
		{"callback", CallbackPrefix, "/-/wormhole/oauthmngr"},
		{"ledger capture", CapturePath, "/v1/oauthmngr/capture"},
		{"ledger redeem", RedeemPath, "/v1/oauthmngr/redeem"},
		{"admin API prefix", APIPrefix, "/api/v1/"},
		{"controls", ControlsPath, "/api/v1/state/ctls"},
		{"routes webhook", RoutesWebhookPath, "/api/v1/webhook/routes"},
		{"invalidate webhook", InvalidateWebhookPath, "/api/v1/webhook/invalidate"},
		{"version", VersionPath, "/api/v1/version"},
		{"health", HealthPath, "/api/v1/healthz"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.path != tt.want {
				t.Errorf("path = %q, want %q", tt.path, tt.want)
			}
		})
	}
}
