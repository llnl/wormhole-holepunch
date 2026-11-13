package args

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli/v3"
)

func Test_OauthManagement(t *testing.T) {
	var om OauthManagement
	fb := &FlagBuilder{}
	fb.OauthManagementFlags(&om)

	app := &cli.Command{
		Flags: fb.Flags,
		Action: func(_ context.Context, _ *cli.Command) error {
			return nil
		},
	}

	t.Run("ClientIPCheckEnvironment", func(t *testing.T) {
		for _, value := range []string{"true", "false"} {
			t.Run(value, func(t *testing.T) {
				t.Setenv("HOLEPUNCH_OAUTH_ENABLE_CLIENT_IP_CHECK", value)
				var om OauthManagement
				fb := NewBuilder().OauthManagementFlags(&om)
				cmd := &cli.Command{
					Flags: fb.Flags,
					Action: func(_ context.Context, _ *cli.Command) error {
						return nil
					},
				}

				assert.NoError(t, cmd.Run(t.Context(), []string{"test"}))
				assert.Equal(t, value == "true", om.EnableClientIPCheck)
			})
		}
	})

	t.Run("PopulatesDestination", func(t *testing.T) {
		err := app.Run(t.Context(), []string{
			"test",
			"--" + oauthCookieMaxAgeName, "43200",
			"--" + oauthCookieNameName, "_wormhole_session",
			"--" + oauthNonceTTLName, "300",
			"--" + oauthEnableClientIPCheckName,
			"--" + oauthLedgerURLName, "http://oauthmngr.svc:8083",
			"--" + oauthProxyName, "http://oauth2-proxy.svc.cluster.local:4180",
			"--" + oauthProxyCookieNameName, "_oauth2_proxy",
			"--" + oauthProxySessionStore, "redis",
			"--" + oauthStrategyName, "none",
			"--" + oauthUserAuthURLName, "https://oauth2-proxy.example.com",
		})

		assert.NoError(t, err)

		assert.Equal(t, 43200, om.CookieMaxAge)
		assert.Equal(t, "_wormhole_session", om.CookieName)
		assert.Equal(t, 300, om.NonceTTL)
		assert.True(t, om.EnableClientIPCheck)
		assert.Equal(t, "http://oauthmngr.svc:8083", om.OauthLedgerURL)
		assert.Equal(t, "http://oauth2-proxy.svc.cluster.local:4180", om.InternalProxyURL)
		assert.Equal(t, "_oauth2_proxy", om.ProxyCookieName)
		assert.Equal(t, "redis", om.ProxySessionStore)
		assert.Equal(t, "none", om.Strategy)
		assert.Equal(t, "https://oauth2-proxy.example.com", om.UserAuthURL)
	})

	t.Run("DefaultsSessionStoreToCookie", func(t *testing.T) {
		var defaults OauthManagement
		fb := &FlagBuilder{}
		fb.OauthManagementFlags(&defaults)

		cmd := &cli.Command{
			Flags:  fb.Flags,
			Action: func(_ context.Context, _ *cli.Command) error { return nil },
		}

		assert.NoError(t, cmd.Run(t.Context(), []string{"test"}))
		assert.Equal(t, "cookie", defaults.ProxySessionStore)
		assert.False(t, defaults.EnableClientIPCheck)
	})
}
