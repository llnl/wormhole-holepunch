package holepunch

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"

	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr"
	"github.com/llnl/wormhole-holepunch/internal/wormhole/registry"
)

func Test_adminCmd_OAuthFlags(t *testing.T) {
	original := *oauthArgs
	logging, routes, storage, tokens, web := *loggingArgs, *routeRegArgs, *storageArgs, *tokenSvcArgs, *webArgs
	t.Cleanup(func() {
		*oauthArgs = original
		*loggingArgs, *routeRegArgs, *storageArgs, *tokenSvcArgs, *webArgs = logging, routes, storage, tokens, web
	})

	for _, strategy := range []string{
		oauthmngr.StrategyNone, oauthmngr.StrategyOauth2ProxyReverse, oauthmngr.StrategyOauth2ProxyMiddleware,
	} {
		t.Run(strategy, func(t *testing.T) {
			cmd := adminCmd()
			called := false
			cmd.Action = func(_ context.Context, _ *cli.Command) error {
				called = true
				assert.Equal(t, strategy, oauthArgs.Strategy)
				assert.Equal(t, "http://oauth2-proxy:4180", oauthArgs.InternalProxyURL)
				assert.Equal(t, "auth.example.com", oauthArgs.UserAuthURL)
				assert.Equal(t, 300, oauthArgs.NonceTTL)
				assert.Equal(t, "http://oauthmngr:8083", oauthArgs.OauthLedgerURL)

				validator, err := oauthmngr.Initialize(nil, nil, logs.InitializeDiscard(), *oauthArgs)
				require.NoError(t, err)
				src, err := keys.NormalizeURL("http://foo.example.com/app")
				require.NoError(t, err)
				expanded := validator.ExpandSources([]registry.RawSource{{ID: "app", Source: src}})
				kinds := make(map[registry.RouteKind]int)
				for _, source := range expanded {
					kinds[source.Kind]++
				}
				expected := map[registry.RouteKind]int{
					registry.RouteKindUpstream: 1,
				}
				switch strategy {
				case oauthmngr.StrategyOauth2ProxyReverse:
					expected[registry.RouteKindOauth2Proxy] = 1
				case oauthmngr.StrategyOauth2ProxyMiddleware:
					expected[registry.RouteKindOauth2Proxy] = 1
					expected[registry.RouteKindOauthCallback] = 2
				}
				assert.Equal(t, expected, kinds)
				return nil
			}
			require.NoError(t, cmd.Run(context.Background(), []string{
				"admin", "--oauth-strategy", strategy,
				"--registry-host", "http://registry:8080",
				"--storage-host", "nats://localhost:4222",
				"--token-host", "http://tokens:8080",
				"--oauth-internal-proxy", "http://oauth2-proxy:4180",
				"--oauth-user-auth-url", "auth.example.com", "--oauth-nonce-ttl", "300",
				"--oauth-ledger-url", "http://oauthmngr:8083",
			}))
			assert.True(t, called)
		})
	}
}
