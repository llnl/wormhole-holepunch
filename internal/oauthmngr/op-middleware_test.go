package oauthmngr

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc/codes"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/ctls/errs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/paths"
	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
	"github.com/llnl/wormhole-holepunch/internal/ctls/streams"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr/ledger"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr/oauthapi"
	"github.com/llnl/wormhole-holepunch/internal/wormhole/registry"
	"github.com/llnl/wormhole-holepunch/test/mocks/mock_streams"
)

const (
	testAuthDomain = "auth.example.com"
	testLedgerURL  = "http://holepunch-oauthmngr.svc:8083"
)

func middlewareArgs() args.OauthManagement {
	return args.OauthManagement{
		Strategy:         StrategyOauth2ProxyMiddleware,
		InternalProxyURL: testProxyURL,
		UserAuthURL:      testAuthDomain,
		OauthLedgerURL:   testLedgerURL,
		NonceTTL:         300,
		CookieMaxAge:     43200,
		CookieName:       "_wormhole_session",
		ProxyCookieName:  "_oauth2_proxy",
		// redis rather than the default, verifying it reaches the session resolver.
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
		"requires ledger URL":           func(a *args.OauthManagement) { a.OauthLedgerURL = "" },
		"requires positive nonce TTL":   func(a *args.OauthManagement) { a.NonceTTL = 0 },
		"requires positive session TTL": func(a *args.OauthManagement) { a.CookieMaxAge = 0 },
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

	t.Run("callback routes forward to the ledger", func(t *testing.T) {
		expanded := m.ExpandSources([]registry.RawSource{source(t, "a", "https://foo.example.com/app")})

		for _, s := range expanded {
			switch s.Kind {
			case registry.RouteKindOauth2Proxy:
				assert.Equal(t, testProxyURL, s.Destination.Raw)
			case registry.RouteKindOauthCallback:
				assert.Equal(t, testLedgerURL, s.Destination.Raw, s.ID)
			case registry.RouteKindUpstream, registry.RouteKindReserved:
			}
		}
	})
}

func Test_middlewareManager_PrepareAuthRedirect(t *testing.T) {
	ctrl := gomock.NewController(t)

	details := requests.RequestDetails{
		Host:   "foo.example.com",
		Scheme: "https",
	}

	t.Run("mints a bound nonce and redirects through the auth domain", func(t *testing.T) {
		m := newTestMiddlewareManager(t, newMemKVStore())

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
		assert.Equal(t, "/", redirect.SetCookie.Path)
		assert.NotEmpty(t, redirect.SetCookie.Value)
		assert.Equal(t, 300, redirect.SetCookie.MaxAge)
		assert.True(t, redirect.SetCookie.HttpOnly)
		assert.True(t, redirect.SetCookie.Secure)
		assert.Equal(t, http.SameSiteLaxMode, redirect.SetCookie.SameSite)
		ctx := context.Background()
		start, err := m.ledger.BeginCapture(ctx, nonce)
		require.NoError(t, err)
		require.NoError(t, m.ledger.AuthorizeCapture(ctx, ledger.AuthorizeRequest{
			Nonce: nonce, Authority: details.Host, BindingSecret: redirect.SetCookie.Value, Challenge: start.Challenge,
		}))
		captured, err := m.ledger.Capture(ctx, ledger.CaptureRequest{
			Nonce: nonce, Authority: testAuthDomain, SessionCookie: "proxy-session", AuthProof: start.AuthProof,
		})
		require.NoError(t, err)
		assert.Equal(t, details.Host, captured.TargetSubdomain)

		redeemed, err := m.ledger.Redeem(context.Background(), ledger.RedeemRequest{
			Nonce: nonce, Authority: details.Host, BindingSecret: redirect.SetCookie.Value,
			Code: captured.RedeemCode,
		})
		require.NoError(t, err)
		assert.Equal(t, "https://foo.example.com/app", redeemed.TargetURL)

		result, sErr := m.ValidateCookies(ctx, requests.RequestDetails{
			Host:    details.Host,
			Headers: map[string]string{keys.CookieHeader: "_wormhole_session=" + redeemed.SessionHandle},
		})
		require.Nil(t, sErr)
		assert.Equal(t, "at:proxy-session", result.AccessToken, "the handle resolves to the captured session")
	})

	t.Run("rejects plain HTTP development endpoints", func(t *testing.T) {
		m := newTestMiddlewareManager(t, mockKVStore(ctrl))
		httpDetails := details
		httpDetails.Scheme = "http"

		redirect, sErr := m.PrepareAuthRedirect("http://foo.example.com/app", httpDetails)

		require.NotNil(t, sErr)
		assert.Nil(t, redirect.SetCookie)
	})

	t.Run("store failure is an internal error", func(t *testing.T) {
		kv := mock_streams.NewMockKVStore(ctrl)
		kv.EXPECT().CreateWithTTL(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("boom"))
		m := newTestMiddlewareManager(t, kv)

		_, sErr := m.PrepareAuthRedirect("https://foo.example.com/app", details)

		require.NotNil(t, sErr)
		assert.Equal(t, int32(codes.Internal), sErr.Code())
	})
}

// issueHostSession completes a middleware flow for host through the ledger, capturing
// proxySession, and returns the host session handle the callback would set as a cookie.
func issueHostSession(t *testing.T, m *middlewareManager, host, proxySession string) string {
	t.Helper()

	ctx := context.Background()

	redirect, sErr := m.PrepareAuthRedirect("https://"+host+"/app", requests.RequestDetails{Host: host, Scheme: "https"})
	require.Nil(t, sErr)

	nonce := strings.TrimPrefix(redirect.SetCookie.Name, oauthapi.BindingCookiePrefix)

	start, err := m.ledger.BeginCapture(ctx, nonce)
	require.NoError(t, err)
	require.NoError(t, m.ledger.AuthorizeCapture(ctx, ledger.AuthorizeRequest{
		Nonce: nonce, Authority: host, BindingSecret: redirect.SetCookie.Value, Challenge: start.Challenge,
	}))

	captured, err := m.ledger.Capture(ctx, ledger.CaptureRequest{
		Nonce: nonce, Authority: testAuthDomain, SessionCookie: proxySession, AuthProof: start.AuthProof,
	})
	require.NoError(t, err)

	redeemed, err := m.ledger.Redeem(ctx, ledger.RedeemRequest{
		Nonce: nonce, Authority: host, BindingSecret: redirect.SetCookie.Value, Code: captured.RedeemCode,
	})
	require.NoError(t, err)

	return redeemed.SessionHandle
}

func Test_middlewareManager_ValidateCookies(t *testing.T) {
	ctrl := gomock.NewController(t)

	validate := func(m *middlewareManager, host, cookieHeader string) (Result, *errs.StatusError) {
		return m.ValidateCookies(context.Background(), requests.RequestDetails{
			Host:    host,
			Headers: map[string]string{keys.CookieHeader: cookieHeader},
		})
	}

	t.Run("resolves the host session and strips it from forwarded header", func(t *testing.T) {
		m := newTestMiddlewareManager(t, newMemKVStore())
		handle := issueHostSession(t, m, "foo.example.com", "proxy-session")

		result, sErr := validate(m, "foo.example.com", "_oauth2_proxy=p; _wormhole_session="+handle+"; a=1")

		require.Nil(t, sErr)
		assert.Equal(t, "at:proxy-session", result.AccessToken)
		assert.Equal(t, "a=1", result.CookieHeader)
	})

	t.Run("a session issued for one host cannot be used on another", func(t *testing.T) {
		m := newTestMiddlewareManager(t, newMemKVStore())
		foo := issueHostSession(t, m, "foo.example.com", "victim-session")
		bar := issueHostSession(t, m, "bar.example.com", "other-session")

		_, sErr := validate(m, "bar.example.com", "_wormhole_session="+foo)
		require.NotNil(t, sErr)
		assert.Equal(t, int32(codes.Unauthenticated), sErr.Code(), "the user is sent to sign in again")

		_, sErr = validate(m, "foo.example.com", "_wormhole_session="+foo)
		require.NotNil(t, sErr, "the copied session was revoked, including on its own host")

		result, sErr := validate(m, "bar.example.com", "_wormhole_session="+bar)
		require.Nil(t, sErr, "bar's own session is unaffected")
		assert.Equal(t, "at:other-session", result.AccessToken)
	})

	t.Run("a legacy cookie holding a raw oauth2-proxy session is not accepted", func(t *testing.T) {
		m := newTestMiddlewareManager(t, newMemKVStore())

		_, sErr := validate(m, "foo.example.com", "_wormhole_session=raw-oauth2-proxy-session")

		require.NotNil(t, sErr)
		assert.Equal(t, int32(codes.Unauthenticated), sErr.Code())
	})

	t.Run("strips custom proxy cookies and stale chunks", func(t *testing.T) {
		a := middlewareArgs()
		a.ProxyCookieName = "_custom_proxy"
		a.CookieName = "_custom_session"
		a.ProxySessionStore = "cookie"
		m, err := newMiddlewareManager(newMemKVStore(), echoProxy(ctrl), ll, a)
		require.NoError(t, err)

		handle := issueHostSession(t, m, "foo.example.com", "session")

		result, sErr := validate(m, "foo.example.com", "a=1; _custom_proxy=p; _custom_proxy_0=x; _custom_proxy_12=y; "+
			"_custom_session="+handle+"; _custom_session_0=s; _custom_session_1=ession; _custom_proxy_extra=keep; b=2")
		require.Nil(t, sErr)
		assert.Equal(t, "at:session", result.AccessToken)
		assert.Equal(t, "a=1; _custom_proxy_extra=keep; b=2", result.CookieHeader)
	})

	t.Run("session rejected by oauth2-proxy is unauthenticated", func(t *testing.T) {
		m := newTestMiddlewareManager(t, newMemKVStore())
		handle := issueHostSession(t, m, "foo.example.com", "rejected")

		_, sErr := validate(m, "foo.example.com", "_wormhole_session="+handle)

		require.NotNil(t, sErr)
		assert.Equal(t, int32(codes.Unauthenticated), sErr.Code())
	})

	t.Run("ignores the oauth2-proxy cookie", func(t *testing.T) {
		m := newTestMiddlewareManager(t, newMemKVStore())

		_, sErr := validate(m, "foo.example.com", "_oauth2_proxy=p")

		require.NotNil(t, sErr)
		assert.Equal(t, int32(codes.Unauthenticated), sErr.Code())
	})

	t.Run("a store outage is an internal error, not a new sign-in", func(t *testing.T) {
		kv := mock_streams.NewMockKVStore(ctrl)
		kv.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("nats unavailable"))
		m := newTestMiddlewareManager(t, kv)

		_, sErr := validate(m, "foo.example.com", "_wormhole_session="+strings.Repeat("A", 43))

		require.NotNil(t, sErr)
		assert.Equal(t, int32(codes.Internal), sErr.Code())
	})
}

// memKVStore is an in-memory streams.KVStore with revision checks, ignoring TTLs.
type memKVStore struct {
	mu       sync.Mutex
	data     map[string][]byte
	revision map[string]uint64
}

func newMemKVStore() *memKVStore {
	return &memKVStore{data: make(map[string][]byte), revision: make(map[string]uint64)}
}

func (s *memKVStore) AllKeys(context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	keys := make([]string, 0, len(s.data))
	for k := range s.data {
		keys = append(keys, k)
	}

	return keys, nil
}

func (s *memKVStore) Create(ctx context.Context, key string, val any) error {
	return s.CreateWithTTL(ctx, key, val, 0)
}

func (s *memKVStore) CreateWithTTL(_ context.Context, key string, val any, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.data[key]; ok {
		return streams.ErrKeyExists
	}

	return s.store(key, val)
}

func (s *memKVStore) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.data, key)
	delete(s.revision, key)

	return nil
}

func (s *memKVStore) Get(ctx context.Context, key string, val any) error {
	_, err := s.GetWithRevision(ctx, key, val)
	return err
}

func (s *memKVStore) GetWithRevision(_ context.Context, key string, val any) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.data[key]
	if !ok {
		return 0, streams.ErrKeyNotFound
	}

	return s.revision[key], json.Unmarshal(b, val)
}

func (s *memKVStore) Put(_ context.Context, key string, val any) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.store(key, val)
}

func (s *memKVStore) UpdateWithRevision(ctx context.Context, key string, val any, revision uint64) error {
	return s.UpdateWithRevisionTTL(ctx, key, val, revision, 0)
}

func (s *memKVStore) UpdateWithRevisionTTL(_ context.Context, key string, val any, revision uint64, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.revision[key] != revision {
		return errors.New("revision mismatch")
	}

	return s.store(key, val)
}

func (s *memKVStore) store(key string, val any) error {
	b, err := json.Marshal(val)
	if err != nil {
		return err
	}

	s.data[key] = b
	s.revision[key]++

	return nil
}
