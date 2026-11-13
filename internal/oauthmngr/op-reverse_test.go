package oauthmngr

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc/codes"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
	"github.com/llnl/wormhole-holepunch/internal/wormhole/registry"
)

const testProxyURL = "http://oauth2-proxy.svc.cluster.local:4180"

func newTestReverseManager(t *testing.T) *reverseManager {
	t.Helper()

	m, err := newReverseManager(echoProxy(gomock.NewController(t)), ll, args.OauthManagement{
		InternalProxyURL: testProxyURL,
		ProxyCookieName:  "_oauth2_proxy",
	})
	require.NoError(t, err)

	return m
}

func Test_newReverseManager(t *testing.T) {
	t.Run("requires internal proxy URL", func(t *testing.T) {
		m, err := newReverseManager(nil, ll, args.OauthManagement{})

		require.Error(t, err)
		assert.Nil(t, m)
	})

	t.Run("rejects unknown session store", func(t *testing.T) {
		m, err := newReverseManager(nil, ll, args.OauthManagement{InternalProxyURL: testProxyURL, ProxySessionStore: "memcached"})

		require.Error(t, err)
		assert.Nil(t, m)
	})
}

func Test_reverseManager_ExpandSources(t *testing.T) {
	m := newTestReverseManager(t)

	t.Run("adds only oauth2-proxy routes on every virtual host", func(t *testing.T) {
		sources := []registry.RawSource{
			source(t, "a", "https://foo.example.com/app"),
			source(t, "b", "https://foo.example.com/other"),
			source(t, "c", "http://bar.example.com/"),
		}

		expanded := m.ExpandSources(sources)

		assert.Equal(t, sources, expanded[:len(sources)])
		assert.Equal(t, []string{
			"oauth2-proxy https://foo.example.com/-/wormhole/oauth2",
			"oauth2-proxy http://bar.example.com/-/wormhole/oauth2",
		}, injected(expanded))
	})

	t.Run("oauth2-proxy routes forward to the internal proxy without rewrite", func(t *testing.T) {
		expanded := m.ExpandSources([]registry.RawSource{source(t, "a", "https://foo.example.com/app")})

		for _, s := range expanded {
			if s.Kind == registry.RouteKindOauth2Proxy {
				assert.Equal(t, testProxyURL, s.Destination.Raw)
				assert.Empty(t, s.PrefixRewrite)
			}
		}
	})

	t.Run("no callback routes are generated", func(t *testing.T) {
		expanded := m.ExpandSources([]registry.RawSource{source(t, "a", "https://foo.example.com/app")})

		for _, s := range expanded {
			assert.NotEqual(t, registry.RouteKindOauthCallback, s.Kind)
		}
	})
}

func Test_reverseManager_PrepareAuthRedirect(t *testing.T) {
	m := newTestReverseManager(t)

	redirect, sErr := m.PrepareAuthRedirect("https://foo.example.com/app?x=1", requests.RequestDetails{
		Host:   "foo.example.com",
		Scheme: "https",
	})

	require.Nil(t, sErr)
	assert.Equal(t,
		"https://foo.example.com/-/wormhole/oauth2/start?rd=https%3A%2F%2Ffoo.example.com%2Fapp%3Fx%3D1",
		redirect.URL,
	)
	assert.Nil(t, redirect.SetCookie)
}

func Test_reverseManager_ValidateCookies(t *testing.T) {
	m := newTestReverseManager(t)

	t.Run("resolves the proxy session and strips it from forwarded header", func(t *testing.T) {
		result, sErr := m.ValidateCookies(context.Background(), requests.RequestDetails{
			Headers: map[string]string{keys.CookieHeader: "a=1; _oauth2_proxy=token; b=2"},
		})

		require.Nil(t, sErr)
		assert.Equal(t, "at:token", result.AccessToken)
		assert.Equal(t, "a=1; b=2", result.CookieHeader)
	})

	t.Run("joins oauth2-proxy chunks with the default cookie store", func(t *testing.T) {
		result, sErr := m.ValidateCookies(context.Background(), requests.RequestDetails{
			Headers: map[string]string{keys.CookieHeader: "a=1; _oauth2_proxy_0=tok; _oauth2_proxy_1=en; b=2"},
		})

		require.Nil(t, sErr)
		assert.Equal(t, "at:token", result.AccessToken)
		assert.Equal(t, "a=1; b=2", result.CookieHeader)
	})

	t.Run("session rejected by oauth2-proxy is unauthenticated", func(t *testing.T) {
		_, sErr := m.ValidateCookies(context.Background(), requests.RequestDetails{
			Headers: map[string]string{keys.CookieHeader: "_oauth2_proxy=rejected"},
		})

		require.NotNil(t, sErr)
		assert.Equal(t, int32(codes.Unauthenticated), sErr.Code())
	})

	t.Run("missing cookie is unauthenticated", func(t *testing.T) {
		_, sErr := m.ValidateCookies(context.Background(), requests.RequestDetails{
			Headers: map[string]string{keys.CookieHeader: "a=1"},
		})

		require.NotNil(t, sErr)
		assert.Equal(t, int32(codes.Unauthenticated), sErr.Code())
	})
}
