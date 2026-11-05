package envoy

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	extauthz "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	wasmfilter "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/wasm/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	wasm "github.com/envoyproxy/go-control-plane/envoy/extensions/wasm/v3"
	resource "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr"
	"github.com/llnl/wormhole-holepunch/internal/wormhole/registry"
	"github.com/llnl/wormhole-holepunch/test/mocks/mock_requests"
	"github.com/llnl/wormhole-holepunch/test/mocks/mock_streams"
)

const (
	testOauthProxyURL = "http://oauth2-proxy.svc:4180"
	testLedgerURL     = "http://holepunch-oauthmngr.svc:8083"
	testWasmPath      = "/etc/envoy/wasm/oauthmngr.wasm"
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
		NonceTTL:          300,
		CookieMaxAge:      43200,
		CookieName:        "_wormhole_session",
		ProxyCookieName:   "_oauth2_proxy",
		ProxySessionStore: "cookie",
	}
}

type oauthSnapshot struct {
	validator oauthmngr.Validator
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

	plugin, err := newOauthPlugin(validator, args.OauthManagement{OauthWasmPath: testWasmPath, OauthLedgerURL: testLedgerURL})
	require.NoError(t, err)

	s := newTestSnapshotServer(t, ctrl)
	s.routeReg = reg
	s.oauthPlugin = plugin

	snap, err := s.generateSnapshot(context.Background())
	require.NoError(t, err)
	require.NoError(t, snap.Consistent())

	routes, ok := snap.GetResources(resource.RouteType)[routeName].(*route.RouteConfiguration)
	require.True(t, ok)

	clusters := make([]string, 0)
	for name := range snap.GetResources(resource.ClusterType) {
		clusters = append(clusters, name)
	}

	slices.Sort(clusters)

	lis, ok := snap.GetResources(resource.ListenerType)[s.listenerName()].(*listener.Listener)
	require.True(t, ok)

	var manager hcm.HttpConnectionManager
	require.NoError(t, lis.GetFilterChains()[0].GetFilters()[0].GetTypedConfig().UnmarshalTo(&manager))

	return oauthSnapshot{validator: validator, routes: routes, clusters: clusters, filters: manager.GetHttpFilters()}
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

// wasmEnabled lists, sorted, every "domain prefix" where the oauthmngr wasm filter runs:
// the filter is enabled in the HCM, so any route not explicitly disabling it.
func (o oauthSnapshot) wasmEnabled(t *testing.T) []string {
	t.Helper()

	enabled := make([]string, 0)

	if !slices.Contains(o.filterNames(), oauthWasmFilter) {
		return enabled
	}

	for key, r := range o.routesBy() {
		cfg, ok := r.GetTypedPerFilterConfig()[oauthWasmFilter]
		if !ok {
			enabled = append(enabled, key)
			continue
		}

		var fc route.FilterConfig
		require.NoError(t, cfg.UnmarshalTo(&fc), key)
		assert.Nil(t, fc.GetConfig(), "disabling requires no config")

		if !fc.GetDisabled() {
			enabled = append(enabled, key)
		}
	}

	slices.Sort(enabled)

	return enabled
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
			"auth.example.com /-/wormhole/oauth2",
			"auth.example.com /-/wormhole/oauthmngr",
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
						expected["/-/wormhole/oauth2"] = 1
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

	t.Run("wasm is only enabled on callback routes", func(t *testing.T) {
		assert.Equal(t, []string{
			"auth.example.com /-/wormhole/oauthmngr",
			"bar.example.com /-/wormhole/oauthmngr",
			"foo.example.com /-/wormhole/oauthmngr",
		}, snap.wasmEnabled(t))
	})

	t.Run("callback routes are local 404 replies", func(t *testing.T) {
		for _, key := range []string{
			"auth.example.com /-/wormhole/oauthmngr",
			"bar.example.com /-/wormhole/oauthmngr",
			"foo.example.com /-/wormhole/oauthmngr",
		} {
			require.Contains(t, routes, key)
			assert.Equal(t, uint32(404), routes[key].GetDirectResponse().GetStatus(), key)
			assert.Nil(t, routes[key].GetRoute(), key)
		}
	})

	t.Run("oauth2-proxy route forwards without host rewrite", func(t *testing.T) {
		r := routes["auth.example.com /-/wormhole/oauth2"]
		require.NotNil(t, r)

		assert.Equal(t, "wh_oauth2-proxy.svc_4180", r.GetRoute().GetCluster())
		assert.Nil(t, r.GetRoute().GetHostRewriteSpecifier())
		assert.Empty(t, r.GetRoute().GetPrefixRewrite())
	})

	t.Run("oauth2-proxy is only routed on the auth domain", func(t *testing.T) {
		assert.NotContains(t, routes, "foo.example.com /-/wormhole/oauth2")
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

	t.Run("clusters exclude local reply routes and include the ledger", func(t *testing.T) {
		assert.Equal(t, []string{
			"oauthmngr_ledger",
			"wh_bar-svc_8080",
			"wh_foo-svc_8080",
			"wh_oauth2-proxy.svc_4180",
		}, snap.clusters)
	})

	t.Run("wasm filter precedes ext_authz and fails closed", func(t *testing.T) {
		assert.Equal(t, []string{headerMutationFilter, oauthWasmFilter, authzFilter, httpRouteFilter}, snap.filterNames())

		f := snap.filters[1]
		assert.False(t, f.GetDisabled(), "enabled in the HCM, disabled per route")

		var plugin wasmfilter.Wasm
		require.NoError(t, f.GetTypedConfig().UnmarshalTo(&plugin))
		assert.Equal(t, wasm.FailurePolicy_FAIL_CLOSED, plugin.GetConfig().GetFailurePolicy())
		assert.Equal(t, testWasmPath, plugin.GetConfig().GetVmConfig().GetCode().GetLocal().GetFilename())

		var raw wrapperspb.StringValue
		require.NoError(t, plugin.GetConfig().GetConfiguration().UnmarshalTo(&raw))

		var cfg oauthmngr.PluginConfig
		require.NoError(t, json.Unmarshal([]byte(raw.GetValue()), &cfg))

		expected, _ := snap.validator.WasmPluginConfig()
		assert.Equal(t, *expected, cfg)
	})
}

func Test_oauthSnapshot_noPlugin(t *testing.T) {
	for _, strategy := range []string{oauthmngr.StrategyNone, oauthmngr.StrategyOauth2ProxyReverse} {
		t.Run(strategy, func(t *testing.T) {
			snap := newOauthSnapshot(t, strategy)

			assert.Equal(t, []string{headerMutationFilter, authzFilter, httpRouteFilter}, snap.filterNames())
			assert.Empty(t, snap.wasmEnabled(t))
			assert.NotContains(t, snap.clusters, "oauthmngr_ledger")
		})
	}
}

func Test_newOauthPlugin(t *testing.T) {
	ll := logs.InitializeDiscard()
	ctrl := gomock.NewController(t)

	middleware, err := oauthmngr.Initialize(mock_streams.NewMockKVStore(ctrl), nil, ll, oauthArgs(oauthmngr.StrategyOauth2ProxyMiddleware))
	require.NoError(t, err)

	valid := args.OauthManagement{OauthWasmPath: testWasmPath, OauthLedgerURL: testLedgerURL}

	t.Run("no plugin for strategies without one", func(t *testing.T) {
		plugin, err := newOauthPlugin(oauthmngr.Disabled(), args.OauthManagement{})

		require.NoError(t, err)
		assert.Nil(t, plugin)
	})

	t.Run("valid", func(t *testing.T) {
		plugin, err := newOauthPlugin(middleware, valid)

		require.NoError(t, err)
		assert.Equal(t, "holepunch-oauthmngr.svc", plugin.ledgerURL.Hostname())
	})

	invalid := map[string]args.OauthManagement{
		"missing wasm path":  {OauthLedgerURL: testLedgerURL},
		"missing ledger URL": {OauthWasmPath: testWasmPath},
		"ledger URL no host": {OauthWasmPath: testWasmPath, OauthLedgerURL: "/relative"},
	}

	for name, xdsArgs := range invalid {
		t.Run(name, func(t *testing.T) {
			_, err := newOauthPlugin(middleware, xdsArgs)
			require.Error(t, err)
		})
	}

	for _, ledgerURL := range []string{
		"//ledger:8083", "ftp://ledger", "http://ledger:0", "https://ledger:65536",
		"http://ledger:", "http://ledger:abc", "http://user:password@ledger",
		"http://ledger/prefix", "http://ledger/?query=1", "http://ledger?",
		"http://ledger/#fragment", "http://", "://bad",
	} {
		t.Run(ledgerURL, func(t *testing.T) {
			_, err := newOauthPlugin(middleware, args.OauthManagement{
				OauthWasmPath: testWasmPath, OauthLedgerURL: ledgerURL,
			})
			require.Error(t, err)
		})
	}
}

func Test_ledgerCluster(t *testing.T) {
	ctrl := gomock.NewController(t)

	middleware, err := oauthmngr.Initialize(mock_streams.NewMockKVStore(ctrl), nil, logs.InitializeDiscard(), oauthArgs(oauthmngr.StrategyOauth2ProxyMiddleware))
	require.NoError(t, err)

	tests := []struct {
		url, host string
		port      uint32
		https     bool
		ip        bool
	}{
		{url: testLedgerURL, host: "holepunch-oauthmngr.svc", port: 8083},
		{url: "http://ledger/", host: "ledger", port: 80},
		{url: "http://ledger:65535", host: "ledger", port: 65535},
		{url: "https://ledger", host: "ledger", port: 443, https: true},
		{url: "https://ledger:8443/", host: "ledger", port: 8443, https: true},
		{url: "https://127.0.0.1", host: "127.0.0.1", port: 443, https: true, ip: true},
	}
	for _, tc := range tests {
		t.Run(tc.url, func(t *testing.T) {
			plugin, err := newOauthPlugin(middleware, args.OauthManagement{
				OauthWasmPath: testWasmPath, OauthLedgerURL: tc.url,
			})
			require.NoError(t, err)
			c := plugin.ledgerCluster(durationpb.New(time.Second))
			require.NoError(t, c.ValidateAll())
			assert.Equal(t, "oauthmngr_ledger", c.GetName())
			assert.Equal(t, cluster.Cluster_LOGICAL_DNS, c.GetType())
			addr := c.GetLoadAssignment().GetEndpoints()[0].GetLbEndpoints()[0].GetEndpoint().GetAddress().GetSocketAddress()
			assert.Equal(t, tc.host, addr.GetAddress())
			assert.Equal(t, tc.port, addr.GetPortValue())
			if !tc.https {
				assert.Nil(t, c.GetTransportSocket(), "HTTP must remain plaintext")
				return
			}
			require.NotNil(t, c.GetTransportSocket())
			assert.Equal(t, "envoy.transport_sockets.tls", c.GetTransportSocket().GetName())
			var ctx tls.UpstreamTlsContext
			require.NoError(t, c.GetTransportSocket().GetTypedConfig().UnmarshalTo(&ctx))
			require.NoError(t, ctx.ValidateAll())
			validation := ctx.GetCommonTlsContext().GetValidationContext()
			require.NotNil(t, validation)
			require.NotNil(t, validation.GetSystemRootCerts())
			assert.Nil(t, validation.GetTrustedCa())
			require.Len(t, validation.GetMatchTypedSubjectAltNames(), 1)
			san := validation.GetMatchTypedSubjectAltNames()[0]
			assert.Equal(t, tc.host, san.GetMatcher().GetExact())
			if tc.ip {
				assert.Empty(t, ctx.GetSni())
				assert.Equal(t, tls.SubjectAltNameMatcher_IP_ADDRESS, san.GetSanType())
			} else {
				assert.Equal(t, tc.host, ctx.GetSni())
				assert.Equal(t, tls.SubjectAltNameMatcher_DNS, san.GetSanType())
			}
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
