package args

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli/v3"
)

func Test_TokenServiceFlags(t *testing.T) {
	var ts TokenService
	fb := &FlagBuilder{}
	fb.TokenServiceFlags(&ts)
	fb.GlobalFlags(&GlobalSettings{})

	app := &cli.Command{
		Flags: fb.Flags,
		Action: func(_ context.Context, _ *cli.Command) error {
			return nil
		},
	}

	t.Run("token header debug", func(t *testing.T) {
		err := app.Run(t.Context(), []string{
			"test",
			"--" + tokenHeaderDebugName, "true",
			"--" + tokenHostName, "http://token-host.example.test",
		})

		assert.ErrorContains(t, err, "--development")
	})

	t.Run("dev host debug", func(t *testing.T) {
		err := app.Run(t.Context(), []string{
			"test",
			"--" + devHostHeaderName, "test",
			"--" + tokenHostName, "http://token-host.example.test",
		})

		assert.ErrorContains(t, err, "--development")
	})

	t.Run("PopulatesDestination", func(t *testing.T) {
		err := app.Run(t.Context(), []string{
			"test",
			"--" + develName, "true",
			"--" + tokenCipherKeyName, "cipher-key-override",
			"--" + tokenExchangePathName, "/exchange/jwt",
			"--" + tokenHeaderName, "x-user-token",
			"--" + tokenHeaderDebugName, "true",
			"--" + tokenHostName, "http://token-host.example.test",
			"--" + tokenServiceAdminName, "admin-token-override",
			"--" + oauthExchangePathName, "/exchange/oauth",
			"--" + oauthProxyName, "http://oauth-proxy.example.test",
			"--" + subtokenHeaderName, "x-custom-subtoken",
			"--" + subtokenPathName, "/admin/subtoken",
			"--" + devHostHeaderName, "x-dev-host",
		})

		assert.NoError(t, err)

		assert.Equal(t, "cipher-key-override", ts.TokenCipherKey)
		assert.Equal(t, "/exchange/jwt", ts.TokenExchangePath)
		assert.Equal(t, "x-user-token", ts.TokenHeader)
		assert.Equal(t, true, ts.TokenHeaderDebug)
		assert.Equal(t, "http://token-host.example.test", ts.TokenHost)
		assert.Equal(t, "admin-token-override", ts.TokenServiceAdmin)
		assert.Equal(t, "/exchange/oauth", ts.OauthExchangePath)
		assert.Equal(t, "http://oauth-proxy.example.test", ts.OauthProxy)
		assert.Equal(t, "x-custom-subtoken", ts.SubtokenHeader)
		assert.Equal(t, "/admin/subtoken", ts.SubtokenPath)
		assert.Equal(t, "x-dev-host", ts.DevHostHeader)
	})
}
