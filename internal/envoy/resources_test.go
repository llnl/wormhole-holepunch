package envoy

import (
	"fmt"
	"net/url"
	"testing"
	"time"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	"github.com/stretchr/testify/assert"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
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
}
