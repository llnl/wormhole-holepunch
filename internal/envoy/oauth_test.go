package envoy

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	extauthz "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	resource "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr"
	"github.com/llnl/wormhole-holepunch/internal/wormhole/registry"
	"github.com/llnl/wormhole-holepunch/test/mocks/mock_requests"
	"github.com/llnl/wormhole-holepunch/test/mocks/mock_streams"
)

const (
	testOauthProxyURL = "http://oauth2-proxy.svc:4180"
	testLedgerURL     = "http://holepunch-oauthmngr.svc:8083"
)

// staticSources are the user routes for every oauth snapshot test.
const staticSources = `sources: [
  {id: "4ff69450-30eb-489b-bb90-15f25cd88c7d", src: "https://foo.example.com", dst: "http://foo-svc:8080"},
  {id: "1f959cc7-9376-4485-b291-1675aa6445ea", src: "http://foo.example.com/bar", dst: "http://foo-svc:8080"},
  {id: "db348f08-888c-4c73-8e15-21d85866b344", src: "https://foo.example.com:8443/foo", dst: "http://foo-svc:8080"},
  {id: "43208434-df8d-4111-92ea-b29843e3f006", src: "https://bar.example.com/api", dst: "http://bar-svc:8080"},
]`

func oauthArgs(strategy string) args.OauthManagement {
	return args.OauthManagement{
		Strategy:          strategy,
		InternalProxyURL:  testOauthProxyURL,
		UserAuthURL:       "auth.example.com",
		OauthLedgerURL:    testLedgerURL,
		NonceTTL:          300,
		CookieMaxAge:      43200,
		CookieName:        "_wormhole_session",
		ProxyCookieName:   "_oauth2_proxy",
		ProxySessionStore: "cookie",
	}
}

type oauthSnapshot struct {
	routes    *route.RouteConfiguration
	clusters  []string
	filters   []*hcm.HttpFilter
}

// newOauthSnapshot generates a snapshot exactly as the envoy-xds command would: the real
// registry (static sources) expanded by the real oauthmngr strategy.
func newOauthSnapshot(t *testing.T, strategy string) oauthSnapshot {
	t.Helper()

	ctrl := gomock.NewController(t)
	ll := logs.InitializeDiscard()

	validator, err := oauthmngr.Initialize(mock_streams.NewMockKVStore(ctrl), nil, ll, oauthArgs(strategy))
	require.NoError(t, err)

	staticFile := filepath.Join(t.TempDir(), "static.yaml")
	require.NoError(t, os.WriteFile(staticFile, []byte(staticSources), 0o600))

	reg, err := registry.Initialize(
		context.Background(),
		mock_requests.NewMockClient(ctrl),
		mock_streams.NewMockPubSub(ctrl),
		args.RouteRegistry{RegistryHost: "http://registry", StaticCfg: staticFile},
		ll,
		registry.WithSourceExpander(validator.ExpandSources),
	)
	require.NoError(t, err)

	s := newTestSnapshotServer(t, ctrl)
	s.routeReg = reg

	snap, err := s.generateSnapshot(context.Background())
	require.NoError(t, err)
	require.NoError(t, snap.Consistent())

	routes, ok := snap.GetResources(resource.RouteType)[routeName].(*route.RouteConfiguration)
	require.True(t, ok)
	require.NoError(t, routes.ValidateAll())

	clusters := make([]string, 0)
	for name := range snap.GetResources(resource.ClusterType) {
		clusters = append(clusters, name)
	}

	slices.Sort(clusters)

	lis, ok := snap.GetResources(resource.ListenerType)[s.listenerName()].(*listener.Listener)
	require.True(t, ok)

	var manager hcm.HttpConnectionManager
	require.NoError(t, lis.GetFilterChains()[0].GetFilters()[0].GetTypedConfig().UnmarshalTo(&manager))

	return oauthSnapshot{routes: routes, clusters: clusters, filters: manager.GetHttpFilters()}
}

// routesBy indexes every route as "domain prefix".
func (o oauthSnapshot) routesBy() map[string]*route.Route {
	out := make(map[string]*route.Route)

	for _, vh := range o.routes.GetVirtualHosts() {
		for _, r := range vh.GetRoutes() {
			out[vh.GetDomains()[0]+" "+r.GetMatch().GetPrefix()] = r
		}
	}

	return out
}

// authzDisabled lists, sorted, every "domain prefix" with ext_authz disabled.
func (o oauthSnapshot) authzDisabled(t *testing.T) []string {
	t.Helper()

	disabled := make([]string, 0)

	for key, r := range o.routesBy() {
		var perRoute extauthz.ExtAuthzPerRoute
		require.NoError(t, r.GetTypedPerFilterConfig()[authzFilter].UnmarshalTo(&perRoute), key)

		if perRoute.GetDisabled() {
			disabled = append(disabled, key)
		}
	}

	slices.Sort(disabled)

	return disabled
}

func (o oauthSnapshot) filterNames() []string {
	names := make([]string, 0, len(o.filters))
	for _, f := range o.filters {
		names = append(names, f.GetName())
	}

	return names
}

// Test_oauthSnapshot_authzDisabled is the security-critical assertion of the design: the
// only (host, prefix) pairs reachable without ext_authz are those generated for the strategy.
func Test_oauthSnapshot_authzDisabled(t *testing.T) {
	tests := map[string][]string{
		oauthmngr.StrategyNone: {},
		oauthmngr.StrategyOauth2ProxyReverse: {
			"bar.example.com /-/wormhole/oauth2",
			"foo.example.com /-/wormhole/oauth2",
		},
		oauthmngr.StrategyOauth2ProxyMiddleware: {
			"auth.example.com /-/wormhole/oauthmngr",
			"auth.example.com /oauth2",
			"bar.example.com /-/wormhole/oauthmngr",
			"foo.example.com /-/wormhole/oauthmngr",
		},
	}

	for strategy, expected := range tests {
		t.Run(strategy, func(t *testing.T) {
			snap := newOauthSnapshot(t, strategy)

			assert.Equal(t, expected, snap.authzDisabled(t))
		})
	}
}

func Test_oauthSnapshot_sharedHost(t *testing.T) {
	for _, strategy := range []string{
		oauthmngr.StrategyNone, oauthmngr.StrategyOauth2ProxyReverse, oauthmngr.StrategyOauth2ProxyMiddleware,
	} {
		t.Run(strategy, func(t *testing.T) {
			snap := newOauthSnapshot(t, strategy)
			expectedHosts := 2
			if strategy == oauthmngr.StrategyOauth2ProxyMiddleware {
				expectedHosts++
			}
			require.Len(t, snap.routes.GetVirtualHosts(), expectedHosts)

			hosts := make(map[string]bool)
			for _, vh := range snap.routes.GetVirtualHosts() {
				host := vh.GetDomains()[0]
				assert.False(t, hosts[host], "duplicate virtual host: %s", host)
				hosts[host] = true
				counts := make(map[string]int)
				for _, r := range vh.GetRoutes() {
					counts[r.GetMatch().GetPrefix()]++
				}
				assert.NotContains(t, counts, "/-/wormhole", "OAuth must not reserve the entire prefix")
				expected := make(map[string]int)
				switch host {
				case "foo.example.com":
					expected["/"] = 1
					expected["/foo"] = 1
					expected["/bar"] = 1
				case "bar.example.com":
					expected["/api"] = 1
				}
				switch strategy {
				case oauthmngr.StrategyOauth2ProxyReverse:
					expected["/-/wormhole/oauth2"] = 1
				case oauthmngr.StrategyOauth2ProxyMiddleware:
					expected["/-/wormhole/oauthmngr"] = 1
					if host == "auth.example.com" {
						expected["/oauth2"] = 1
					}
				}
				assert.Equal(t, expected, counts, host)
			}
		})
	}
}

func Test_oauthSnapshot_middleware(t *testing.T) {
	snap := newOauthSnapshot(t, oauthmngr.StrategyOauth2ProxyMiddleware)
	routes := snap.routesBy()

	t.Run("callback routes forward to the ledger without host rewrite", func(t *testing.T) {
		for _, key := range []string{
			"auth.example.com /-/wormhole/oauthmngr",
			"bar.example.com /-/wormhole/oauthmngr",
			"foo.example.com /-/wormhole/oauthmngr",
		} {
			require.Contains(t, routes, key)
			assert.Equal(t, "wh_holepunch-oauthmngr.svc_8083", routes[key].GetRoute().GetCluster(), key)
			assert.Nil(t, routes[key].GetRoute().GetHostRewriteSpecifier(), key)
			assert.Empty(t, routes[key].GetRoute().GetPrefixRewrite(), key)
		}
	})

	t.Run("callback routes bind the client address, host, and scheme", func(t *testing.T) {
		headers := make(map[string]string)

		for _, h := range routes["foo.example.com /-/wormhole/oauthmngr"].GetRequestHeadersToAdd() {
			assert.Equal(t, core.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD, h.GetAppendAction(), h.GetHeader().GetKey())
			headers[h.GetHeader().GetKey()] = h.GetHeader().GetValue()
		}

		assert.Equal(t, map[string]string{
			keys.ClientIPHeader:       "%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%",
			keys.WormholeHostHeader:   "foo.example.com",
			keys.WormholeSchemeHeader: "https",
		}, headers)
	})

	t.Run("only callback routes add request headers", func(t *testing.T) {
		for key, r := range routes {
			if r.GetMatch().GetPrefix() != "/-/wormhole/oauthmngr" {
				assert.Empty(t, r.GetRequestHeadersToAdd(), key)
			}
		}
	})

	t.Run("oauth2-proxy route forwards without host rewrite", func(t *testing.T) {
		r := routes["auth.example.com /oauth2"]
		require.NotNil(t, r)

		assert.Equal(t, "wh_oauth2-proxy.svc_4180", r.GetRoute().GetCluster())
		assert.Nil(t, r.GetRoute().GetHostRewriteSpecifier())
		assert.Empty(t, r.GetRoute().GetPrefixRewrite())
	})

	t.Run("oauth2-proxy is only routed on the auth domain", func(t *testing.T) {
		assert.NotContains(t, routes, "foo.example.com /oauth2")
	})

	t.Run("user routes are unchanged", func(t *testing.T) {
		r := routes["foo.example.com /"]
		require.NotNil(t, r)

		assert.Equal(t, "wh_foo-svc_8080", r.GetRoute().GetCluster())
		assert.Equal(t, "foo-svc:8080", r.GetRoute().GetHostRewriteLiteral())
	})

	t.Run("host port is ignored when matching virtual hosts", func(t *testing.T) {
		assert.True(t, snap.routes.GetIgnorePortInHostMatching())
	})

	t.Run("routes are ordered longest prefix first", func(t *testing.T) {
		for _, vh := range snap.routes.GetVirtualHosts() {
			prefixes := make([]int, 0)
			for _, r := range vh.GetRoutes() {
				prefixes = append(prefixes, len(r.GetMatch().GetPrefix()))
			}

			assert.True(t, slices.IsSortedFunc(prefixes, func(a, b int) int { return b - a }), vh.GetDomains())
		}
	})

	t.Run("clusters include the ledger", func(t *testing.T) {
		assert.Equal(t, []string{
			"wh_bar-svc_8080",
			"wh_foo-svc_8080",
			"wh_holepunch-oauthmngr.svc_8083",
			"wh_oauth2-proxy.svc_4180",
		}, snap.clusters)
	})
}

func Test_oauthSnapshot_filterChain(t *testing.T) {
	for _, strategy := range []string{
		oauthmngr.StrategyNone, oauthmngr.StrategyOauth2ProxyReverse, oauthmngr.StrategyOauth2ProxyMiddleware,
	} {
		t.Run(strategy, func(t *testing.T) {
			snap := newOauthSnapshot(t, strategy)

			assert.Equal(t, []string{headerMutationFilter, authzFilter, httpRouteFilter}, snap.filterNames())
		})
	}
}

func Test_makeHTTPListener_clientAddress(t *testing.T) {
	manager := func(t *testing.T, xdsArgs args.XDS) *hcm.HttpConnectionManager {
		t.Helper()

		s := newTestSnapshotServer(t, gomock.NewController(t))
		s.xdsArgs.UseRemoteAddress = xdsArgs.UseRemoteAddress

		var m hcm.HttpConnectionManager
		lis := s.makeHTTPListener("l", routeName)
		require.NoError(t, lis.GetFilterChains()[0].GetFilters()[0].GetTypedConfig().UnmarshalTo(&m))

		return &m
	}

	t.Run("defaults preserve existing behavior", func(t *testing.T) {
		m := manager(t, args.XDS{})

		assert.False(t, m.GetUseRemoteAddress().GetValue())
		assert.Zero(t, m.GetXffNumTrustedHops())
	})

	t.Run("edge proxy uses connection address", func(t *testing.T) {
		m := manager(t, args.XDS{UseRemoteAddress: true})

		assert.True(t, m.GetUseRemoteAddress().GetValue())
		assert.Zero(t, m.GetXffNumTrustedHops())
	})
}
