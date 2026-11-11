package oauthmngr

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc/codes"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/paths"
	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
	"github.com/llnl/wormhole-holepunch/internal/ctls/streams"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr/oauthapi"
	"github.com/llnl/wormhole-holepunch/internal/wormhole/registry"
	"github.com/llnl/wormhole-holepunch/test/mocks/mock_streams"
)

const testAuthDomain = "auth.example.com"

func middlewareArgs() args.OauthManagement {
	return args.OauthManagement{
		Strategy:         StrategyOauth2ProxyMiddleware,
		InternalProxyURL: testProxyURL,
		UserAuthURL:      testAuthDomain,
		NonceTTL:         300,
		CookieMaxAge:     43200,
		CookieName:       "_wormhole_session",
		ProxyCookieName:  "_oauth2_proxy",
		// redis rather than the default, verifying it reaches the plugin configuration.
		ProxySessionStore: "redis",
	}
}

func newTestMiddlewareManager(t *testing.T, kvStore streams.KVStore) *middlewareManager {
	t.Helper()

	m, err := newMiddlewareManager(kvStore, echoProxy(gomock.NewController(t)), ll, middlewareArgs())
	require.NoError(t, err)

	return m
}

func Test_newMiddlewareManager(t *testing.T) {
	ctrl := gomock.NewController(t)

	tests := map[string]func(*args.OauthManagement){
		"requires internal proxy URL":   func(a *args.OauthManagement) { a.InternalProxyURL = "" },
		"requires user auth URL":        func(a *args.OauthManagement) { a.UserAuthURL = "" },
		"requires positive nonce TTL":   func(a *args.OauthManagement) { a.NonceTTL = 0 },
		"rejects unknown session store": func(a *args.OauthManagement) { a.ProxySessionStore = "memcached" },
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			a := middlewareArgs()
			mutate(&a)

			m, err := newMiddlewareManager(mockKVStore(ctrl), nil, ll, a)

			require.Error(t, err)
			assert.Nil(t, m)
		})
	}
}

func Test_middlewareManager_ExpandSources(t *testing.T) {
	ctrl := gomock.NewController(t)
	m := newTestMiddlewareManager(t, mockKVStore(ctrl))

	t.Run("auth domain routes are always established", func(t *testing.T) {
		expanded := m.ExpandSources(nil)

		assert.Equal(t, []string{
			"oauth2-proxy https://auth.example.com/oauth2",
			"oauth-callback https://auth.example.com/-/wormhole/oauthmngr",
		}, injected(expanded))
	})

	t.Run("oauth2-proxy only on the auth domain, callback everywhere", func(t *testing.T) {
		sources := []registry.RawSource{
			source(t, "a", "https://foo.example.com/app"),
			source(t, "b", "https://auth.example.com/landing"),
			source(t, "c", "https://foo.example.com/other"),
		}

		expanded := m.ExpandSources(sources)

		assert.Equal(t, sources, expanded[:len(sources)])
		assert.Equal(t, []string{
			"oauth2-proxy https://auth.example.com/oauth2",
			"oauth-callback https://auth.example.com/-/wormhole/oauthmngr",
			"oauth-callback https://foo.example.com/-/wormhole/oauthmngr",
		}, injected(expanded))
	})

	t.Run("auth URL with a port", func(t *testing.T) {
		a := middlewareArgs()
		a.UserAuthURL = "auth.example.com:3128"

		withPort, err := newMiddlewareManager(mockKVStore(ctrl), nil, ll, a)
		require.NoError(t, err)

		assert.Contains(t, injected(withPort.ExpandSources(nil)),
			"oauth2-proxy https://auth.example.com/oauth2")
	})

	t.Run("only oauth2-proxy routes forward upstream", func(t *testing.T) {
		expanded := m.ExpandSources([]registry.RawSource{source(t, "a", "https://foo.example.com/app")})

		for _, s := range expanded {
			switch s.Kind {
			case registry.RouteKindOauth2Proxy:
				assert.Equal(t, testProxyURL, s.Destination.Raw)
			case registry.RouteKindOauthCallback:
				assert.Nil(t, s.Destination.URL, s.ID)
			case registry.RouteKindUpstream:
			}
		}
	})
}

func Test_middlewareManager_PrepareAuthRedirect(t *testing.T) {
	ctrl := gomock.NewController(t)

	details := requests.RequestDetails{
		Host:     "foo.example.com",
		Scheme:   "https",
		ClientIP: "10.0.0.1",
	}

	t.Run("mints a bound nonce and redirects through the auth domain", func(t *testing.T) {
		kv := mock_streams.NewMockKVStore(ctrl)
		var (
			stored   []byte
			flowKey  string
			revision uint64 = 1
		)
		kv.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(_ context.Context, key string, value any) error {
				flowKey = key
				var err error
				stored, err = json.Marshal(value)
				return err
			},
		)
		kv.EXPECT().GetWithRevision(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(_ context.Context, key string, value any) (uint64, error) {
				assert.Equal(t, flowKey, key)
				return revision, json.Unmarshal(stored, value)
			},
		).Times(2)
		kv.EXPECT().UpdateWithRevision(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(_ context.Context, key string, value any, expectedRevision uint64) error {
				assert.Equal(t, flowKey, key)
				assert.Equal(t, revision, expectedRevision)
				revision++
				var err error
				stored, err = json.Marshal(value)
				return err
			},
		).Times(2)
		kv.EXPECT().Delete(gomock.Any(), gomock.Any()).DoAndReturn(
			func(_ context.Context, key string) error {
				assert.Equal(t, flowKey, key)
				return nil
			},
		)
		m := newTestMiddlewareManager(t, kv)

		redirect, sErr := m.PrepareAuthRedirect("https://foo.example.com/app", details)
		require.Nil(t, sErr)

		u, err := url.Parse(redirect.URL)
		require.NoError(t, err)
		assert.Equal(t, "auth.example.com", u.Host)
		assert.Equal(t, "/oauth2/start", u.Path)

		rd, err := url.Parse(u.Query().Get("rd"))
		require.NoError(t, err)
		assert.Equal(t, "auth.example.com", rd.Host)
		assert.Equal(t, paths.CallbackPrefix, rd.Path)

		nonce := rd.Query().Get("nonce")
		assert.True(t, oauthapi.ValidNonce(nonce))

		require.NotNil(t, redirect.SetCookie)
		assert.Equal(t, oauthapi.BindingCookieName(nonce), redirect.SetCookie.Name)
		assert.Equal(t, paths.CallbackPrefix, redirect.SetCookie.Path)
		assert.NotEmpty(t, redirect.SetCookie.Value)
		assert.Equal(t, 300, redirect.SetCookie.MaxAge)
		assert.True(t, redirect.SetCookie.HttpOnly)
		assert.True(t, redirect.SetCookie.Secure)
		assert.Equal(t, http.SameSiteLaxMode, redirect.SetCookie.SameSite)
		captured, err := m.ledger.Capture(context.Background(), oauthapi.CaptureRequest{
			Nonce: nonce, ClientIP: details.ClientIP, Authority: testAuthDomain, SessionCookie: "proxy-session",
		})
		require.NoError(t, err)
		assert.Equal(t, details.Host, captured.TargetSubdomain)
		assert.Equal(t, "https://foo.example.com"+paths.CallbackPrefix+"?nonce="+nonce, captured.CallbackURL)

		redeemed, err := m.ledger.Redeem(context.Background(), oauthapi.RedeemRequest{
			Nonce: nonce, ClientIP: details.ClientIP, Authority: details.Host, BindingSecret: redirect.SetCookie.Value,
		})
		require.NoError(t, err)
		assert.Equal(t, "proxy-session", redeemed.SessionCookie)
		assert.Equal(t, "https://foo.example.com/app", redeemed.TargetURL)
	})

	t.Run("requires a client IP for binding", func(t *testing.T) {
		m := newTestMiddlewareManager(t, mockKVStore(ctrl))

		_, sErr := m.PrepareAuthRedirect("https://foo.example.com/app", requests.RequestDetails{Host: "foo.example.com"})

		require.NotNil(t, sErr)
		assert.Equal(t, int32(codes.Internal), sErr.Code())
	})

	t.Run("allows plain HTTP development endpoints", func(t *testing.T) {
		m := newTestMiddlewareManager(t, mockKVStore(ctrl))
		httpDetails := details
		httpDetails.Scheme = "http"

		redirect, sErr := m.PrepareAuthRedirect("http://foo.example.com/app", httpDetails)

		require.Nil(t, sErr)
		require.NotNil(t, redirect.SetCookie)
		assert.False(t, redirect.SetCookie.Secure)
		assert.True(t, redirect.SetCookie.HttpOnly)
		assert.Empty(t, redirect.SetCookie.Domain)
	})

	t.Run("store failure is an internal error", func(t *testing.T) {
		kv := mock_streams.NewMockKVStore(ctrl)
		kv.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("boom"))
		m := newTestMiddlewareManager(t, kv)

		_, sErr := m.PrepareAuthRedirect("https://foo.example.com/app", details)

		require.NotNil(t, sErr)
		assert.Equal(t, int32(codes.Internal), sErr.Code())
	})
}

func Test_middlewareManager_ValidateCookies(t *testing.T) {
	ctrl := gomock.NewController(t)
	m := newTestMiddlewareManager(t, mockKVStore(ctrl))

	t.Run("resolves the session cookie and strips it from forwarded header", func(t *testing.T) {
		result, sErr := m.ValidateCookies(context.Background(), requests.RequestDetails{
			Headers: map[string]string{keys.CookieHeader: "_oauth2_proxy=p; _wormhole_session=s; a=1"},
		})

		require.Nil(t, sErr)
		assert.Equal(t, "at:s", result.AccessToken)
		assert.Equal(t, "_oauth2_proxy=p; a=1", result.CookieHeader)
	})

	t.Run("session rejected by oauth2-proxy is unauthenticated", func(t *testing.T) {
		_, sErr := m.ValidateCookies(context.Background(), requests.RequestDetails{
			Headers: map[string]string{keys.CookieHeader: "_wormhole_session=rejected"},
		})

		require.NotNil(t, sErr)
		assert.Equal(t, int32(codes.Unauthenticated), sErr.Code())
	})

	t.Run("ignores the oauth2-proxy cookie", func(t *testing.T) {
		_, sErr := m.ValidateCookies(context.Background(), requests.RequestDetails{
			Headers: map[string]string{keys.CookieHeader: "_oauth2_proxy=p"},
		})

		require.NotNil(t, sErr)
		assert.Equal(t, int32(codes.Unauthenticated), sErr.Code())
	})
}

func Test_middlewareManager_WasmPluginConfig(t *testing.T) {
	ctrl := gomock.NewController(t)

	cfg, ok := newTestMiddlewareManager(t, mockKVStore(ctrl)).WasmPluginConfig()

	require.True(t, ok)
	assert.Equal(t, &PluginConfig{
		AuthDomain:          testAuthDomain,
		ProxyCookieName:     "_oauth2_proxy",
		SessionCookieName:   "_wormhole_session",
		SessionCookieMaxAge: 43200,
		ProxySessionStore:   oauthapi.SessionStoreRedis,
		LedgerCluster:       "oauthmngr_ledger",
		LedgerTimeoutMs:     2000,
	}, cfg)
}
