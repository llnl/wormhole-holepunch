package oauthmngr

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/paths"
	"github.com/llnl/wormhole-holepunch/internal/wormhole/registry"
)

// source builds a minimal raw source for the provided source URL.
func source(t *testing.T, id, src string) registry.RawSource {
	t.Helper()

	u, err := keys.NormalizeURL(src)
	require.NoError(t, err)

	return registry.RawSource{ID: id, Source: u, Destination: urlString("http://upstream.svc:8080")}
}

func Test_virtualHosts(t *testing.T) {
	t.Run("de-duplicates by hostname in order observed", func(t *testing.T) {
		vhosts := virtualHosts([]registry.RawSource{
			source(t, "a", "https://foo.example.com/app"),
			source(t, "b", "https://foo.example.com:8443/other"),
			source(t, "c", "http://foo.example.com/"),
			source(t, "d", "bar.example.com"),
			source(t, "e", "http://bar.example.com/foo"),
		})

		assert.Equal(t, []virtualHost{
			{scheme: "https", host: "foo.example.com"},
			{scheme: "http", host: "bar.example.com"},
		}, vhosts)
	})

	t.Run("preserves configured scheme regardless of path port and input order", func(t *testing.T) {
		sources := []registry.RawSource{
			source(t, "a", "http://foo.example.com"),
			source(t, "b", "http://foo.example.com:8443/bar"),
			source(t, "c", "http://foo.example.com:8080/foo"),
		}
		expected := []virtualHost{{scheme: "http", host: "foo.example.com"}}
		assert.Equal(t, expected, virtualHosts(sources))
		slices.Reverse(sources)
		assert.Equal(t, expected, virtualHosts(sources))
	})

	t.Run("skips sources without a parsed URL", func(t *testing.T) {
		assert.Empty(t, virtualHosts([]registry.RawSource{{ID: "empty"}}))
	})
}

func Test_ExpandSources_sharedHost(t *testing.T) {
	for _, strategy := range []string{StrategyNone, StrategyOauth2ProxyReverse, StrategyOauth2ProxyMiddleware} {
		t.Run(strategy, func(t *testing.T) {
			cfg := middlewareArgs()
			cfg.Strategy = strategy
			validator, err := Initialize(nil, nil, ll, cfg)
			require.NoError(t, err)

			for _, scheme := range []string{"https", "http"} {
				t.Run(scheme, func(t *testing.T) {
					sources := []registry.RawSource{
						source(t, "root", scheme+"://foo.example.com"),
						source(t, "bar", scheme+"://foo.example.com/bar"),
						source(t, "foo", scheme+"://foo.example.com:8080/foo"),
						source(t, "other", "https://other.example.com/app"),
						source(t, "auth-root", "https://auth.example.com"),
						source(t, "auth-bar", "https://auth.example.com/bar"),
						source(t, "auth-foo", "https://auth.example.com:8080/foo"),
					}
					original := slices.Clone(sources)
					expanded := validator.ExpandSources(sources)
					assert.Equal(t, original, sources, "input sources must not be modified")
					assert.Equal(t, original, expanded[:len(original)], "all application routes must remain")
					for _, src := range expanded[len(original):] {
						assert.NotEqual(t, registry.RouteKindReserved, src.Kind, "OAuth must not reserve the prefix")
					}

					counts := make(map[string]map[registry.RouteKind]int)
					ids := make(map[string]struct{})
					for _, src := range expanded[len(original):] {
						_, duplicate := ids[src.ID]
						assert.False(t, duplicate, "duplicate injected ID: %s", src.ID)
						ids[src.ID] = struct{}{}
						host := src.Source.URL.Hostname()
						if counts[host] == nil {
							counts[host] = make(map[registry.RouteKind]int)
						}
						counts[host][src.Kind]++
						expectedScheme := "https"
						if host == "foo.example.com" {
							expectedScheme = scheme
						}
						assert.Equal(t, expectedScheme, src.Source.URL.Scheme)
					}

					if strategy == StrategyNone {
						assert.Len(t, expanded, len(original))
						require.Empty(t, counts)
					} else {
						require.Len(t, counts, 3)
					}
					for host, kinds := range counts {
						expected := make(map[registry.RouteKind]int)
						switch strategy {
						case StrategyOauth2ProxyReverse:
							expected[registry.RouteKindOauth2Proxy] = 1
						case StrategyOauth2ProxyMiddleware:
							expected[registry.RouteKindOauthCallback] = 1
							if host == testAuthDomain {
								expected[registry.RouteKindOauth2Proxy] = 1
							}
						}
						assert.Equal(t, expected, kinds, host)
					}

					slices.Reverse(sources)
					reordered := validator.ExpandSources(sources)
					assert.ElementsMatch(t, expanded[len(original):], reordered[len(original):],
						"injected sources must be stable when application routes are reordered")
				})
			}
		})
	}
}

func Test_newRoute(t *testing.T) {
	vh := virtualHost{scheme: "https", host: "foo.example.com"}

	t.Run("forwarding route", func(t *testing.T) {
		route := newRoute(vh, paths.Oauth2ProxyPrefix, registry.RouteKindOauth2Proxy, "http://proxy.svc:4180")

		assert.Equal(t, "wormhole-oauth2-proxy-foo.example.com", route.ID)
		assert.Equal(t, "https://foo.example.com/-/wormhole/oauth2", route.Source.Raw)
		assert.Equal(t, "http://proxy.svc:4180", route.Destination.Raw)
		assert.Equal(t, registry.RouteKindOauth2Proxy, route.Kind)
		assert.True(t, route.NoAuth)
	})

	t.Run("local reply route has no destination", func(t *testing.T) {
		route := newRoute(vh, paths.CallbackPrefix, registry.RouteKindOauthCallback, "")

		assert.Equal(t, "https://foo.example.com/-/wormhole/oauthmngr", route.Source.Raw)
		assert.Nil(t, route.Destination.URL)
		assert.Equal(t, registry.RouteKindOauthCallback, route.Kind)
		assert.True(t, route.NoAuth)
	})
}

// injected filters the sources down to those added by ExpandSources, keyed as
// "kind host+path" for readable assertions.
func injected(sources []registry.RawSource) []string {
	out := make([]string, 0)

	for _, s := range sources {
		if s.Kind == registry.RouteKindUpstream {
			continue
		}

		out = append(out, s.Kind.String()+" "+s.Source.Raw)
	}

	return out
}
