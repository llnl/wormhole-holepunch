package envoy

import (
	"fmt"
	"net/url"
	"testing"
	"time"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	trace "github.com/envoyproxy/go-control-plane/envoy/config/trace/v3"
	fileaccesslog "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/file/v3"
	extauthz "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	header_mutation "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_mutation/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/wormhole/registry"
)

func Test_xdsServer_makeClusters(t *testing.T) {
	t.Run("basic cluster", func(t *testing.T) {
		s := &xdsServer{
			xdsArgs: args.XDS{
				ConnectTimeout: 5 * time.Second,
			},
		}

		ctls := map[string]registry.ProxyControls{
			"service1": {
				Destination: keys.URLString{
					URL: &url.URL{Scheme: "http", Host: "service1.local:80"},
				},
			},
			"service2": {
				Destination: keys.URLString{
					URL: &url.URL{Scheme: "http", Host: "service2.local:8080"},
				},
			},
		}

		got := s.makeClusters(ctls)

		assert.Len(t, got, 2)

		if len(got) == 2 {
			c0 := got[0].(*cluster.Cluster)
			c1 := got[1].(*cluster.Cluster)

			// There is no guarantee of order when it comes to clusters, nor
			// is it required (unlike routes).
			if c0.GetName() == "wh_service1.local_80" {
				assert.Equal(t, int64(5), c1.ConnectTimeout.Seconds)
				assert.Equal(t, "wh_service2.local_8080", c1.GetName())
			} else {
				assert.Equal(t, int64(5), c0.ConnectTimeout.Seconds)
				assert.Equal(t, "wh_service2.local_8080", c0.GetName())
			}
		}
	})

	t.Run("deduplicates shared destination", func(t *testing.T) {
		s := &xdsServer{
			xdsArgs: args.XDS{ConnectTimeout: 5 * time.Second},
		}

		ctls := map[string]registry.ProxyControls{
			"route-a": {
				Source:      keys.URLString{URL: &url.URL{Scheme: "http", Host: "src-a.local"}},
				Destination: keys.URLString{URL: &url.URL{Scheme: "http", Host: "shared.local:80"}},
			},
			"route-b": {
				Source:      keys.URLString{URL: &url.URL{Scheme: "http", Host: "src-b.local"}},
				Destination: keys.URLString{URL: &url.URL{Scheme: "http", Host: "shared.local:80"}},
			},
		}

		got := s.makeClusters(ctls)

		require.Len(t, got, 1)
		assert.Equal(t, "wh_shared.local_80", got[0].(*cluster.Cluster).GetName())
	})

	t.Run("cluster name matches load assignment cluster name", func(t *testing.T) {
		s := &xdsServer{
			xdsArgs: args.XDS{ConnectTimeout: 5 * time.Second},
		}

		ctls := map[string]registry.ProxyControls{
			"some-route-id": {
				Destination: keys.URLString{URL: &url.URL{Scheme: "http", Host: "backend.local:9000"}},
			},
		}

		got := s.makeClusters(ctls)

		require.Len(t, got, 1)
		c := got[0].(*cluster.Cluster)
		assert.Equal(t, c.GetName(), c.GetLoadAssignment().GetClusterName())
	})

	t.Run("empty controls returns no clusters", func(t *testing.T) {
		s := &xdsServer{}

		got := s.makeClusters(map[string]registry.ProxyControls{})

		assert.Empty(t, got)
	})
}

func Test_makeEndpoint(t *testing.T) {
	t.Run("single endpoint", func(t *testing.T) {
		clusterName := "test-cluster"
		dst, _ := url.Parse("http://example.com:8080")

		got := makeEndpoint(clusterName, dst)

		endpoint := got.GetEndpoints()[0].GetLbEndpoints()[0].GetHostIdentifier().(*endpoint.LbEndpoint_Endpoint)

		assert.Equal(t, "test-cluster", got.GetClusterName())
		assert.Equal(t, uint32(8080), endpoint.Endpoint.Address.GetSocketAddress().GetPortValue())
		assert.Equal(t, "example.com", endpoint.Endpoint.Address.GetSocketAddress().GetAddress())
	})
}

func Test_xdsServer_makeRoutes(t *testing.T) {
	t.Run("organized routes", func(t *testing.T) {
		s := &xdsServer{
			xdsArgs: args.XDS{
				ConnectTimeout: 5 * time.Second,
				IdleTimeout:    10 * time.Second,
			},
		}

		ctls := map[string]registry.ProxyControls{
			"route1": {
				Source: keys.URLString{
					URL: &url.URL{Scheme: "http", Host: "source.local", Path: "/base"},
				},
				Destination: keys.URLString{
					URL: &url.URL{Scheme: "http", Host: "destination1.local"},
				},
			},
			"route2": {
				Source: keys.URLString{
					URL: &url.URL{Scheme: "http", Host: "source.local", Path: "/route2"},
				},
				Destination: keys.URLString{
					URL: &url.URL{Scheme: "http", Host: "destination2.local"},
				},
				PrefixRewrite: "/newroute2",
			},
			"route3": {
				Source: keys.URLString{
					URL: &url.URL{Scheme: "http", Host: "source.local", Path: ""},
				},
				Destination: keys.URLString{
					URL: &url.URL{Scheme: "http", Host: "destination3.local"},
				},
			},
		}

		got := s.makeRoutes("test-route", ctls)

		assert.Equal(t, "test-route", got.GetName())
		assert.Len(t, got.VirtualHosts, 1)

		if len(got.VirtualHosts) == 1 {
			assert.Equal(t, "75645aacedb1cba255ae054937c54ea4677f90c0c751aad7ad69139dcecfc016", got.VirtualHosts[0].GetName())
			assert.Len(t, got.VirtualHosts[0].GetRoutes(), 3)

			if len(got.VirtualHosts[0].GetRoutes()) == 3 {
				// Verify expected order
				assert.Equal(t, "/route2", got.VirtualHosts[0].GetRoutes()[0].GetMatch().GetPrefix())
				assert.Equal(t, "/base", got.VirtualHosts[0].GetRoutes()[1].GetMatch().GetPrefix())
				assert.Equal(t, "/", got.VirtualHosts[0].GetRoutes()[2].GetMatch().GetPrefix())
			}
		}
	})

	t.Run("single route w/headers", func(t *testing.T) {
		s := &xdsServer{
			xdsArgs: args.XDS{
				ConnectTimeout: 5 * time.Second,
				IdleTimeout:    10 * time.Second,
			},
		}

		ctls := map[string]registry.ProxyControls{
			"route1": {
				Source: keys.URLString{
					URL: &url.URL{Scheme: "http", Host: "source.local", Path: "/base"},
				},
				Destination: keys.URLString{
					URL: &url.URL{Scheme: "http", Host: "destination1.local"},
				},
				RequestHeaders: map[string]string{
					"hello": "world!",
					"foo":   "bar",
				},
			},
		}

		got := s.makeRoutes("test-route", ctls)

		assert.Equal(t, "test-route", got.GetName())
		assert.Len(t, got.VirtualHosts, 1)

		if len(got.VirtualHosts) == 1 {
			assert.Len(t, got.VirtualHosts[0].GetRoutes(), 1)

			if len(got.VirtualHosts[0].GetRoutes()) == 1 {
				mutationsRaw := fmt.Sprintf(
					"%+v",
					got.VirtualHosts[0].GetRoutes()[0].GetTypedPerFilterConfig()["envoy.filters.http.header_mutation"],
				)

				// This isn't an ideal way to parse the protobuf, I should refactor slightly
				// when time allows to more easily test the header manipulation function.
				assert.Contains(t, mutationsRaw, "world!")
				assert.Contains(t, mutationsRaw, "bar")
			}
		}
	})

	t.Run("multiple virtual hosts for different source domains", func(t *testing.T) {
		s := &xdsServer{
			xdsArgs: args.XDS{
				ConnectTimeout: 5 * time.Second,
				IdleTimeout:    10 * time.Second,
			},
		}

		ctls := map[string]registry.ProxyControls{
			"r1": {
				Source:      keys.URLString{URL: &url.URL{Scheme: "http", Host: "host-a.local", Path: "/"}},
				Destination: keys.URLString{URL: &url.URL{Scheme: "http", Host: "dst1.local"}},
			},
			"r2": {
				Source:      keys.URLString{URL: &url.URL{Scheme: "http", Host: "host-b.local", Path: "/"}},
				Destination: keys.URLString{URL: &url.URL{Scheme: "http", Host: "dst2.local"}},
			},
		}

		got := s.makeRoutes("test-route", ctls)

		assert.Len(t, got.GetVirtualHosts(), 2)
	})

	t.Run("localhost source uses wildcard domain", func(t *testing.T) {
		s := &xdsServer{
			xdsArgs: args.XDS{
				ConnectTimeout: 5 * time.Second,
				IdleTimeout:    10 * time.Second,
			},
		}

		ctls := map[string]registry.ProxyControls{
			"r1": {
				Source:      keys.URLString{URL: &url.URL{Scheme: "http", Host: "localhost:8080", Path: "/api"}},
				Destination: keys.URLString{URL: &url.URL{Scheme: "http", Host: "backend.local"}},
			},
		}

		got := s.makeRoutes("test-route", ctls)

		require.Len(t, got.GetVirtualHosts(), 1)
		assert.Equal(t, []string{"*"}, got.GetVirtualHosts()[0].GetDomains())
	})

	t.Run("route action targets correct cluster and rewrites host", func(t *testing.T) {
		s := &xdsServer{
			xdsArgs: args.XDS{
				ConnectTimeout: 5 * time.Second,
				IdleTimeout:    10 * time.Second,
				RequestTimeout: 30 * time.Second,
			},
		}

		ctls := map[string]registry.ProxyControls{
			"r1": {
				Source:        keys.URLString{URL: &url.URL{Scheme: "http", Host: "src.local", Path: "/app"}},
				Destination:   keys.URLString{URL: &url.URL{Scheme: "http", Host: "backend.local:9090"}},
				PrefixRewrite: "/",
			},
		}

		got := s.makeRoutes("test-route", ctls)

		require.Len(t, got.GetVirtualHosts(), 1)
		require.Len(t, got.GetVirtualHosts()[0].GetRoutes(), 1)

		routeAction := got.GetVirtualHosts()[0].GetRoutes()[0].GetRoute()
		assert.Equal(t, "wh_backend.local_9090", routeAction.GetCluster())
		assert.Equal(t, "backend.local:9090", routeAction.GetHostRewriteLiteral())
		assert.Equal(t, "/", routeAction.GetPrefixRewrite())
		assert.Equal(t, int64(10), routeAction.GetIdleTimeout().GetSeconds())
		assert.Equal(t, int64(30), routeAction.GetTimeout().GetSeconds())
	})

	t.Run("websocket upgrade in route action when enabled", func(t *testing.T) {
		s := &xdsServer{
			xdsArgs: args.XDS{
				ConnectTimeout:  5 * time.Second,
				IdleTimeout:     10 * time.Second,
				EnableWebSocket: true,
			},
		}

		ctls := map[string]registry.ProxyControls{
			"r1": {
				Source:      keys.URLString{URL: &url.URL{Scheme: "http", Host: "src.local", Path: "/"}},
				Destination: keys.URLString{URL: &url.URL{Scheme: "http", Host: "backend.local"}},
			},
		}

		got := s.makeRoutes("test-route", ctls)

		require.Len(t, got.GetVirtualHosts()[0].GetRoutes(), 1)

		upgrades := got.GetVirtualHosts()[0].GetRoutes()[0].GetRoute().GetUpgradeConfigs()
		require.Len(t, upgrades, 1)
		assert.Equal(t, "websocket", upgrades[0].GetUpgradeType())
	})

	t.Run("authz per-route context extensions reflect route config", func(t *testing.T) {
		s := &xdsServer{
			xdsArgs: args.XDS{
				ConnectTimeout: 5 * time.Second,
				IdleTimeout:    10 * time.Second,
			},
		}

		ctls := map[string]registry.ProxyControls{
			"my-route-uuid": {
				Source:      keys.URLString{URL: &url.URL{Scheme: "https", Host: "src.example.com", Path: "/api"}},
				Destination: keys.URLString{URL: &url.URL{Scheme: "http", Host: "backend.local"}},
				CommunityID: "comm-uuid-789",
			},
		}

		got := s.makeRoutes("test-route", ctls)

		require.Len(t, got.GetVirtualHosts(), 1)
		require.Len(t, got.GetVirtualHosts()[0].GetRoutes(), 1)

		filterCfg := got.GetVirtualHosts()[0].GetRoutes()[0].GetTypedPerFilterConfig()[authzFilter]
		require.NotNil(t, filterCfg)

		perRoute := &extauthz.ExtAuthzPerRoute{}
		require.NoError(t, filterCfg.UnmarshalTo(perRoute))

		ctxExt := perRoute.GetCheckSettings().GetContextExtensions()
		assert.Equal(t, "my-route-uuid", ctxExt[keys.PikoHeader])
		assert.Equal(t, "src.example.com", ctxExt[keys.WormholeHostHeader])
		assert.Equal(t, "https", ctxExt[keys.WormholeSchemeHeader])
		assert.Equal(t, "comm-uuid-789", ctxExt[keys.CommunityHeader])
	})

	t.Run("empty controls returns empty virtual hosts", func(t *testing.T) {
		s := &xdsServer{}

		got := s.makeRoutes("test-route", map[string]registry.ProxyControls{})

		assert.Equal(t, "test-route", got.GetName())
		assert.Empty(t, got.GetVirtualHosts())
	})
}

func Test_xdsServer_makeHTTPListener(t *testing.T) {
	t.Run("basic listener", func(t *testing.T) {
		s := &xdsServer{
			xdsArgs: args.XDS{
				ListenerAddress: "0.0.0.0",
				ListenerPort:    8080,
				EnableWebSocket: true,
			},
		}

		listenerName := "test-listener"

		got := s.makeHTTPListener(listenerName, "test-route")

		socketAddress := got.Address.GetSocketAddress()

		assert.Equal(t, listenerName, got.GetName())
		assert.Equal(t, "0.0.0.0", socketAddress.GetAddress())
		assert.Equal(t, uint32(8080), socketAddress.GetPortValue())
	})

	t.Run("http filter chain order", func(t *testing.T) {
		s := &xdsServer{
			xdsArgs: args.XDS{
				ListenerAddress: "0.0.0.0",
				ListenerPort:    8080,
				AuthCluster:     "auth",
				AuthTimeout:     200 * time.Millisecond,
			},
			tokenSvcArgs: args.TokenService{
				TokenHeader:    "x-token",
				SubtokenHeader: "x-subtoken",
			},
		}

		got := s.makeHTTPListener("test-listener", "test-route")

		hcmAny := got.GetFilterChains()[0].GetFilters()[0].GetTypedConfig()
		manager := &hcm.HttpConnectionManager{}
		require.NoError(t, hcmAny.UnmarshalTo(manager))

		filters := manager.GetHttpFilters()
		require.Len(t, filters, 3)
		assert.Equal(t, headerMutationFilter, filters[0].GetName())
		assert.Equal(t, authzFilter, filters[1].GetName())
		assert.Equal(t, httpRouteFilter, filters[2].GetName())
	})

	t.Run("route config name propagated to rds", func(t *testing.T) {
		s := &xdsServer{
			xdsArgs: args.XDS{
				ListenerAddress: "0.0.0.0",
				ListenerPort:    8080,
				AuthCluster:     "auth",
				AuthTimeout:     200 * time.Millisecond,
			},
			tokenSvcArgs: args.TokenService{
				TokenHeader:    "x-token",
				SubtokenHeader: "x-subtoken",
			},
		}

		got := s.makeHTTPListener("test-listener", "my-route-config")

		hcmAny := got.GetFilterChains()[0].GetFilters()[0].GetTypedConfig()
		manager := &hcm.HttpConnectionManager{}
		require.NoError(t, hcmAny.UnmarshalTo(manager))

		assert.Equal(t, "my-route-config", manager.GetRds().GetRouteConfigName())
	})

	t.Run("access log writes to stdout", func(t *testing.T) {
		s := &xdsServer{
			xdsArgs: args.XDS{
				ListenerAddress: "0.0.0.0",
				ListenerPort:    8080,
				AuthCluster:     "auth",
				AuthTimeout:     200 * time.Millisecond,
			},
			tokenSvcArgs: args.TokenService{
				TokenHeader:    "x-token",
				SubtokenHeader: "x-subtoken",
			},
		}

		got := s.makeHTTPListener("test-listener", "test-route")

		hcmAny := got.GetFilterChains()[0].GetFilters()[0].GetTypedConfig()
		manager := &hcm.HttpConnectionManager{}
		require.NoError(t, hcmAny.UnmarshalTo(manager))

		require.Len(t, manager.GetAccessLog(), 1)

		fal := &fileaccesslog.FileAccessLog{}
		require.NoError(t, manager.GetAccessLog()[0].GetTypedConfig().UnmarshalTo(fal))
		assert.Equal(t, "/dev/stdout", fal.GetPath())
	})

	t.Run("websocket upgrade in manager when enabled", func(t *testing.T) {
		s := &xdsServer{
			xdsArgs: args.XDS{
				ListenerAddress: "0.0.0.0",
				ListenerPort:    8080,
				AuthCluster:     "auth",
				AuthTimeout:     200 * time.Millisecond,
				EnableWebSocket: true,
			},
			tokenSvcArgs: args.TokenService{
				TokenHeader:    "x-token",
				SubtokenHeader: "x-subtoken",
			},
		}

		got := s.makeHTTPListener("test-listener", "test-route")

		hcmAny := got.GetFilterChains()[0].GetFilters()[0].GetTypedConfig()
		manager := &hcm.HttpConnectionManager{}
		require.NoError(t, hcmAny.UnmarshalTo(manager))

		require.Len(t, manager.GetUpgradeConfigs(), 1)
		assert.Equal(t, "websocket", manager.GetUpgradeConfigs()[0].GetUpgradeType())
	})

	t.Run("websocket upgrade absent when disabled", func(t *testing.T) {
		s := &xdsServer{
			xdsArgs: args.XDS{
				ListenerAddress: "0.0.0.0",
				ListenerPort:    8080,
				AuthCluster:     "auth",
				AuthTimeout:     200 * time.Millisecond,
				EnableWebSocket: false,
			},
			tokenSvcArgs: args.TokenService{
				TokenHeader:    "x-token",
				SubtokenHeader: "x-subtoken",
			},
		}

		got := s.makeHTTPListener("test-listener", "test-route")

		hcmAny := got.GetFilterChains()[0].GetFilters()[0].GetTypedConfig()
		manager := &hcm.HttpConnectionManager{}
		require.NoError(t, hcmAny.UnmarshalTo(manager))

		assert.Empty(t, manager.GetUpgradeConfigs())
	})

	t.Run("tracing config populated when collector enabled", func(t *testing.T) {
		s := &xdsServer{
			xdsArgs: args.XDS{
				ListenerAddress:  "0.0.0.0",
				ListenerPort:     8080,
				AuthCluster:      "auth",
				AuthTimeout:      200 * time.Millisecond,
				CollectorEnabled: true,
				CollectorCluster: "otel-collector",
				CollectorService: "holepunch",
			},
			tokenSvcArgs: args.TokenService{
				TokenHeader:    "x-token",
				SubtokenHeader: "x-subtoken",
			},
		}

		got := s.makeHTTPListener("test-listener", "test-route")

		hcmAny := got.GetFilterChains()[0].GetFilters()[0].GetTypedConfig()
		manager := &hcm.HttpConnectionManager{}
		require.NoError(t, hcmAny.UnmarshalTo(manager))

		tracing := manager.GetTracing()
		require.NotNil(t, tracing)
		assert.Equal(t, "envoy.tracers.opentelemetry", tracing.GetProvider().GetName())

		otelCfg := &trace.OpenTelemetryConfig{}
		require.NoError(t, tracing.GetProvider().GetTypedConfig().UnmarshalTo(otelCfg))
		assert.Equal(t, "otel-collector", otelCfg.GetGrpcService().GetEnvoyGrpc().GetClusterName())
		assert.Equal(t, "holepunch", otelCfg.GetServiceName())
	})

	t.Run("tracing config absent when collector disabled", func(t *testing.T) {
		s := &xdsServer{
			xdsArgs: args.XDS{
				ListenerAddress:  "0.0.0.0",
				ListenerPort:     8080,
				AuthCluster:      "auth",
				AuthTimeout:      200 * time.Millisecond,
				CollectorEnabled: false,
			},
			tokenSvcArgs: args.TokenService{
				TokenHeader:    "x-token",
				SubtokenHeader: "x-subtoken",
			},
		}

		got := s.makeHTTPListener("test-listener", "test-route")

		hcmAny := got.GetFilterChains()[0].GetFilters()[0].GetTypedConfig()
		manager := &hcm.HttpConnectionManager{}
		require.NoError(t, hcmAny.UnmarshalTo(manager))

		assert.Nil(t, manager.GetTracing())
	})
}

func Test_domain(t *testing.T) {
	t.Run("regular domain", func(t *testing.T) {
		u := &url.URL{Host: "example.com"}
		assert.Equal(t, "example.com", domain(u))
	})

	t.Run("localhost returns wildcard", func(t *testing.T) {
		u := &url.URL{Host: "localhost"}
		assert.Equal(t, "*", domain(u))
	})

	t.Run("loopback ip returns wildcard", func(t *testing.T) {
		u := &url.URL{Host: "127.0.0.1"}
		assert.Equal(t, "*", domain(u))
	})
}

func Test_virtualHostName(t *testing.T) {
	t.Run("deterministic hash", func(t *testing.T) {
		// SHA256 of "source.local" — consistent with the makeRoutes organized-routes test.
		assert.Equal(
			t,
			"75645aacedb1cba255ae054937c54ea4677f90c0c751aad7ad69139dcecfc016",
			virtualHostName("source.local"),
		)
	})

	t.Run("different inputs produce different names", func(t *testing.T) {
		assert.NotEqual(t, virtualHostName("host-a.local"), virtualHostName("host-b.local"))
	})
}

func Test_buildAuthzFilter(t *testing.T) {
	t.Run("context extensions without community", func(t *testing.T) {
		ctl := registry.ProxyControls{
			Source: keys.URLString{URL: &url.URL{Scheme: "https", Host: "src.example.com"}},
		}

		a := buildAuthzFilter(ctl, "route-uuid-123")

		perRoute := &extauthz.ExtAuthzPerRoute{}
		require.NoError(t, a.UnmarshalTo(perRoute))

		ctxExt := perRoute.GetCheckSettings().GetContextExtensions()
		assert.Equal(t, "route-uuid-123", ctxExt[keys.PikoHeader])
		assert.Equal(t, "src.example.com", ctxExt[keys.WormholeHostHeader])
		assert.Equal(t, "https", ctxExt[keys.WormholeSchemeHeader])
		assert.NotContains(t, ctxExt, keys.CommunityHeader)
	})

	t.Run("community id included when set", func(t *testing.T) {
		ctl := registry.ProxyControls{
			Source:      keys.URLString{URL: &url.URL{Scheme: "http", Host: "src.local"}},
			CommunityID: "community-uuid-456",
		}

		a := buildAuthzFilter(ctl, "route-id")

		perRoute := &extauthz.ExtAuthzPerRoute{}
		require.NoError(t, a.UnmarshalTo(perRoute))

		assert.Equal(t, "community-uuid-456", perRoute.GetCheckSettings().GetContextExtensions()[keys.CommunityHeader])
	})

	t.Run("empty community id omitted", func(t *testing.T) {
		ctl := registry.ProxyControls{
			Source:      keys.URLString{URL: &url.URL{Scheme: "http", Host: "src.local"}},
			CommunityID: "",
		}

		a := buildAuthzFilter(ctl, "route-id")

		perRoute := &extauthz.ExtAuthzPerRoute{}
		require.NoError(t, a.UnmarshalTo(perRoute))

		assert.NotContains(t, perRoute.GetCheckSettings().GetContextExtensions(), keys.CommunityHeader)
	})
}

func Test_accessLogCfg(t *testing.T) {
	t.Run("writes to stdout", func(t *testing.T) {
		fal := &fileaccesslog.FileAccessLog{}
		require.NoError(t, accessLogCfg().UnmarshalTo(fal))

		assert.Equal(t, "/dev/stdout", fal.GetPath())
	})

	t.Run("contains all expected fields", func(t *testing.T) {
		fal := &fileaccesslog.FileAccessLog{}
		require.NoError(t, accessLogCfg().UnmarshalTo(fal))

		fields := fal.GetLogFormat().GetJsonFormat().GetFields()

		for _, name := range []string{
			"start_time", "method", "path", "protocol",
			"response_code", "response_flags",
			"bytes_received", "bytes_sent", "duration",
			"upstream_service_time", "x_forwarded_for",
			"user_agent", "request_id", "upstream_host",
			"x_piko_endpoint", "x_wormhole_community",
			"x_wormhole_host", "x_wormhole_scheme",
		} {
			assert.Contains(t, fields, name, "missing access log field %q", name)
		}
	})
}

func Test_xdsServer_authzFilterCfg(t *testing.T) {
	t.Run("grpc cluster and timeout from args", func(t *testing.T) {
		s := &xdsServer{
			xdsArgs: args.XDS{
				AuthCluster: "my-auth-cluster",
				AuthTimeout: 500 * time.Millisecond,
			},
			tokenSvcArgs: args.TokenService{
				TokenHeader:    "x-auth-token",
				SubtokenHeader: "x-sub-token",
			},
		}

		cfg := &extauthz.ExtAuthz{}
		require.NoError(t, s.authzFilterCfg().UnmarshalTo(cfg))

		grpcService := cfg.GetGrpcService()
		require.NotNil(t, grpcService)
		assert.Equal(t, "my-auth-cluster", grpcService.GetEnvoyGrpc().GetClusterName())
		assert.Equal(t, 500*time.Millisecond, grpcService.GetTimeout().AsDuration())
	})

	t.Run("allowed headers contain all expected entries", func(t *testing.T) {
		s := &xdsServer{
			xdsArgs: args.XDS{AuthCluster: "auth", AuthTimeout: 200 * time.Millisecond},
			tokenSvcArgs: args.TokenService{
				TokenHeader:    "x-my-token",
				SubtokenHeader: "x-my-subtoken",
			},
		}

		cfg := &extauthz.ExtAuthz{}
		require.NoError(t, s.authzFilterCfg().UnmarshalTo(cfg))

		var exacts, prefixes []string
		for _, p := range cfg.GetAllowedHeaders().GetPatterns() {
			if e := p.GetExact(); e != "" {
				exacts = append(exacts, e)
			}
			if pr := p.GetPrefix(); pr != "" {
				prefixes = append(prefixes, pr)
			}
		}

		assert.Contains(t, exacts, "x-my-token")
		assert.Contains(t, exacts, "x-my-subtoken")
		assert.Contains(t, exacts, keys.RequestIDHeader)
		assert.Contains(t, exacts, keys.CommunityHeader)
		assert.Contains(t, exacts, "cookie")
		assert.Contains(t, exacts, "upgrade")
		assert.Contains(t, exacts, "connection")
		assert.Contains(t, prefixes, "sec-websocket-")
	})
}

func Test_xdsServer_requestHeaderFilterCfg(t *testing.T) {
	t.Run("custom headers included", func(t *testing.T) {
		s := &xdsServer{
			xdsArgs: args.XDS{VersionHeader: false},
		}

		perRoute := &header_mutation.HeaderMutationPerRoute{}
		require.NoError(t, s.requestHeaderFilterCfg(map[string]string{"x-custom": "value-1"}).UnmarshalTo(perRoute))

		var found bool
		for _, m := range perRoute.GetMutations().GetRequestMutations() {
			if app := m.GetAppend(); app != nil {
				if app.GetHeader().GetKey() == "x-custom" && app.GetHeader().GetValue() == "value-1" {
					found = true
				}
			}
		}
		assert.True(t, found, "expected x-custom header mutation")
	})

	t.Run("version header added when enabled", func(t *testing.T) {
		s := &xdsServer{
			xdsArgs: args.XDS{VersionHeader: true},
		}

		perRoute := &header_mutation.HeaderMutationPerRoute{}
		require.NoError(t, s.requestHeaderFilterCfg(nil).UnmarshalTo(perRoute))

		var found bool
		for _, m := range perRoute.GetMutations().GetRequestMutations() {
			if app := m.GetAppend(); app != nil {
				if app.GetHeader().GetKey() == keys.VersionHeader {
					found = true
				}
			}
		}
		assert.True(t, found, "expected version header mutation")
	})

	t.Run("version header absent when disabled", func(t *testing.T) {
		s := &xdsServer{
			xdsArgs: args.XDS{VersionHeader: false},
		}

		perRoute := &header_mutation.HeaderMutationPerRoute{}
		require.NoError(t, s.requestHeaderFilterCfg(nil).UnmarshalTo(perRoute))

		for _, m := range perRoute.GetMutations().GetRequestMutations() {
			if app := m.GetAppend(); app != nil {
				assert.NotEqual(t, keys.VersionHeader, app.GetHeader().GetKey())
			}
		}
	})
}

func Test_xdsServer_setHeader(t *testing.T) {
	// setHeader is the only resource function that touches s.ll; use a real
	// discard logger so the invalid-input paths don't panic.
	ll := logs.InitializeDiscard()

	t.Run("valid name and value sets header with overwrite action", func(t *testing.T) {
		s := &xdsServer{ll: ll}

		got := s.setHeader("x-custom-header", "some-value")

		require.NotNil(t, got.GetAppend())
		assert.Equal(t, "x-custom-header", got.GetAppend().GetHeader().GetKey())
		assert.Equal(t, "some-value", got.GetAppend().GetHeader().GetValue())
		assert.Equal(t, core.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD, got.GetAppend().GetAppendAction())
	})

	t.Run("empty value is accepted", func(t *testing.T) {
		s := &xdsServer{ll: ll}

		got := s.setHeader("x-empty", "")

		require.NotNil(t, got.GetAppend())
		assert.Equal(t, "x-empty", got.GetAppend().GetHeader().GetKey())
		assert.Equal(t, "", got.GetAppend().GetHeader().GetValue())
	})

	t.Run("tab in value is accepted", func(t *testing.T) {
		s := &xdsServer{ll: ll}

		got := s.setHeader("x-tab-value", "before\tafter")

		require.NotNil(t, got.GetAppend())
		assert.Equal(t, "before\tafter", got.GetAppend().GetHeader().GetValue())
	})

	t.Run("disallowed header name returns empty append", func(t *testing.T) {
		s := &xdsServer{ll: ll}

		for _, name := range []string{"host", "x-forwarded-for", "x-real-ip", "x-envoy-internal", "x-envoy-decorator-operation"} {
			got := s.setHeader(name, "value")

			assert.Nil(t, got.GetAppend().GetHeader(), "expected empty append for disallowed header %q", name)
		}
	})

	t.Run("header name with invalid chars returns empty append", func(t *testing.T) {
		s := &xdsServer{ll: ll}

		for _, name := range []string{"x bad", "x:bad", "x\x00bad", "x(bad)"} {
			got := s.setHeader(name, "value")

			assert.Nil(t, got.GetAppend().GetHeader(), "expected empty append for invalid header name %q", name)
		}
	})

	t.Run("header value with control character returns empty append", func(t *testing.T) {
		s := &xdsServer{ll: ll}

		// \x00 (NUL) and \n (LF) are control chars; \t (HTAB) is explicitly allowed.
		for _, value := range []string{"bad\x00value", "line\nbreak", "carriage\rreturn"} {
			got := s.setHeader("x-valid-name", value)

			assert.Nil(t, got.GetAppend().GetHeader(), "expected empty append for invalid header value %q", value)
		}
	})

	t.Run("well-known internal headers are set correctly", func(t *testing.T) {
		s := &xdsServer{ll: ll}

		cases := []struct{ key, value string }{
			{keys.PikoHeader, "route-uuid"},
			{keys.WormholeHostHeader, "src.example.com"},
			{keys.WormholeSchemeHeader, "https"},
			{keys.CommunityHeader, "comm-uuid"},
			{keys.RequestIDHeader, "req-id-123"},
			{keys.VersionHeader, "v1.2.3"},
		}

		for _, tc := range cases {
			got := s.setHeader(tc.key, tc.value)

			require.NotNil(t, got.GetAppend(), "expected valid mutation for header %q", tc.key)
			assert.Equal(t, tc.key, got.GetAppend().GetHeader().GetKey())
			assert.Equal(t, tc.value, got.GetAppend().GetHeader().GetValue())
			assert.Equal(t, core.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD, got.GetAppend().GetAppendAction())
		}
	})
}
