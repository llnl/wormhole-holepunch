package ledger

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/paths"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr/oauthapi"
)

const (
	testNonce       = "AAAAAAAAAAAAAAAAAAAAAA"
	testCallbackURL = "https://foo.example.com/-/wormhole/oauthmngr?nonce=" + testNonce
)

type stubLedger struct {
	captureErr error
	redeemErr  error
	redeemResp RedeemResponse
	gotCapture CaptureRequest
	gotRedeem  RedeemRequest
}

func (s *stubLedger) Capture(_ context.Context, req CaptureRequest) (CaptureResponse, error) {
	s.gotCapture = req
	if s.captureErr != nil {
		return CaptureResponse{}, s.captureErr
	}

	return CaptureResponse{TargetSubdomain: "foo.example.com", CallbackURL: testCallbackURL}, nil
}

func (s *stubLedger) Redeem(_ context.Context, req RedeemRequest) (RedeemResponse, error) {
	s.gotRedeem = req
	if s.redeemErr != nil {
		return RedeemResponse{}, s.redeemErr
	}

	if s.redeemResp != (RedeemResponse{}) {
		return s.redeemResp, nil
	}

	return RedeemResponse{SessionCookie: "s", TargetURL: "https://foo.example.com/app"}, nil
}

func callbackConfig(store oauthapi.SessionStore) CallbackConfig {
	return CallbackConfig{
		AuthDomain:          "auth.example.com:3128",
		ProxyCookieName:     "_oauth2_proxy",
		ProxySessionStore:   store,
		SessionCookieName:   "_wormhole_session",
		SessionCookieMaxAge: 43200,
	}
}

// callback is a request as forwarded by Envoy's callback route.
type callback struct {
	method  string
	path    string
	host    string
	scheme  string
	cookies []string
	noEnvoy bool
}

func serveCallback(t *testing.T, l Ledger, store oauthapi.SessionStore, c callback) *httptest.ResponseRecorder {
	t.Helper()

	h, err := NewCallbackHandler(l, callbackConfig(store), ll)
	require.NoError(t, err)

	if c.method == "" {
		c.method = http.MethodGet
	}

	if c.path == "" {
		c.path = paths.CallbackPrefix + "?nonce=" + testNonce
	}

	if c.scheme == "" {
		c.scheme = "https"
	}

	req := httptest.NewRequest(c.method, c.path, nil)
	if !c.noEnvoy {
		req.Header.Set(keys.ClientIPHeader, "10.0.0.1")
		req.Header.Set(keys.WormholeHostHeader, c.host)
		req.Header.Set(keys.WormholeSchemeHeader, c.scheme)
	}

	for _, v := range c.cookies {
		req.Header.Add(keys.CookieHeader, v)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	return rec
}

// setCookies indexes the response cookies by name.
func setCookies(rec *httptest.ResponseRecorder) map[string]*http.Cookie {
	out := make(map[string]*http.Cookie)
	for _, c := range rec.Result().Cookies() { //nolint:bodyclose // recorder body
		out[c.Name] = c
	}

	return out
}

func Test_NewCallbackHandler(t *testing.T) {
	_, err := NewCallbackHandler(&stubLedger{}, callbackConfig(oauthapi.SessionStoreCookie), ll)
	require.NoError(t, err)

	invalid := map[string]func(*CallbackConfig){
		"missing auth domain":     func(c *CallbackConfig) { c.AuthDomain = "" },
		"invalid proxy cookie":    func(c *CallbackConfig) { c.ProxyCookieName = "bad;name" },
		"invalid session cookie":  func(c *CallbackConfig) { c.SessionCookieName = "" },
		"non-positive max age":    func(c *CallbackConfig) { c.SessionCookieMaxAge = 0 },
		"unsupported store":       func(c *CallbackConfig) { c.ProxySessionStore = "memcached" },
		"empty store is rejected": func(c *CallbackConfig) { c.ProxySessionStore = "" },
	}

	for name, mutate := range invalid {
		t.Run(name, func(t *testing.T) {
			cfg := callbackConfig(oauthapi.SessionStoreCookie)
			mutate(&cfg)

			_, err := NewCallbackHandler(&stubLedger{}, cfg, ll)
			require.Error(t, err)
		})
	}
}

func Test_callback_rejectedRequests(t *testing.T) {
	tests := map[string]struct {
		c      callback
		status int
	}{
		"missing nonce":   {callback{path: paths.CallbackPrefix, host: "foo.example.com"}, http.StatusBadRequest},
		"malformed nonce": {callback{path: paths.CallbackPrefix + "?nonce=bad", host: "foo.example.com"}, http.StatusBadRequest},
		"repeated nonce": {callback{
			path: paths.CallbackPrefix + "?nonce=" + testNonce + "&nonce=" + testNonce, host: "foo.example.com",
		}, http.StatusBadRequest},
		"not forwarded by envoy": {callback{noEnvoy: true}, http.StatusInternalServerError},
		"method not allowed":     {callback{method: http.MethodPost, host: "foo.example.com"}, http.StatusMethodNotAllowed},
		"sub-path not served":    {callback{path: paths.CallbackPrefix + "/x", host: "foo.example.com"}, http.StatusNotFound},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			stub := &stubLedger{}

			rec := serveCallback(t, stub, oauthapi.SessionStoreCookie, tc.c)

			assert.Equal(t, tc.status, rec.Code)
			assert.Empty(t, stub.gotCapture)
			assert.Empty(t, stub.gotRedeem)
		})
	}
}

func Test_callback_capture(t *testing.T) {
	t.Run("captures the session and redirects to the sub-domain callback", func(t *testing.T) {
		stub := &stubLedger{}

		rec := serveCallback(t, stub, oauthapi.SessionStoreCookie, callback{
			host:    "auth.example.com",
			cookies: []string{"a=1", "_oauth2_proxy=proxy-session"},
		})

		require.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, testCallbackURL, rec.Header().Get("Location"))
		assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
		assert.Equal(t, "no-referrer", rec.Header().Get("Referrer-Policy"))
		assert.Empty(t, rec.Header().Values("Set-Cookie"))
		assert.Equal(t, CaptureRequest{
			Nonce:         testNonce,
			ClientIP:      "10.0.0.1",
			Authority:     "auth.example.com",
			SessionCookie: "proxy-session",
		}, stub.gotCapture)
	})

	t.Run("missing oauth2-proxy cookie", func(t *testing.T) {
		stub := &stubLedger{}

		rec := serveCallback(t, stub, oauthapi.SessionStoreCookie, callback{host: "auth.example.com"})

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Empty(t, stub.gotCapture)
	})

	t.Run("cookie store joins oauth2-proxy chunks", func(t *testing.T) {
		stub := &stubLedger{}

		rec := serveCallback(t, stub, oauthapi.SessionStoreCookie, callback{
			host:    "auth.example.com",
			cookies: []string{"_oauth2_proxy_0=abc", "_oauth2_proxy_1=def"},
		})

		require.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, "abcdef", stub.gotCapture.SessionCookie)
	})

	t.Run("redis store rejects chunks as a misconfiguration", func(t *testing.T) {
		rec := serveCallback(t, &stubLedger{}, oauthapi.SessionStoreRedis, callback{
			host:    "auth.example.com",
			cookies: []string{"_oauth2_proxy_0=abc"},
		})

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	ledgerErrors := map[string]struct {
		err    error
		status int
	}{
		"invalid request":  {ErrInvalidRequest, http.StatusBadRequest},
		"flow unavailable": {ErrFlowUnavailable, http.StatusUnauthorized},
		"binding mismatch": {ErrBindingMismatch, http.StatusUnauthorized},
		"store failure":    {errors.New("boom"), http.StatusInternalServerError},
	}

	for name, tc := range ledgerErrors {
		t.Run(name, func(t *testing.T) {
			rec := serveCallback(t, &stubLedger{captureErr: tc.err}, oauthapi.SessionStoreCookie, callback{
				host:    "auth.example.com",
				cookies: []string{"_oauth2_proxy=proxy-session"},
			})

			assert.Equal(t, tc.status, rec.Code)
			assert.Empty(t, rec.Header().Get("Location"))
		})
	}
}

func Test_callback_redeem(t *testing.T) {
	bindingCookie := oauthapi.BindingCookieName(testNonce)

	t.Run("issues the session cookie and redirects to the target", func(t *testing.T) {
		stub := &stubLedger{}

		rec := serveCallback(t, stub, oauthapi.SessionStoreCookie, callback{
			host:    "foo.example.com",
			cookies: []string{bindingCookie + "=secret"},
		})

		require.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, "https://foo.example.com/app", rec.Header().Get("Location"))
		assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
		assert.Equal(t, RedeemRequest{
			Nonce:         testNonce,
			ClientIP:      "10.0.0.1",
			Authority:     "foo.example.com",
			BindingSecret: "secret",
		}, stub.gotRedeem)

		got := setCookies(rec)
		require.Len(t, got, 2)

		session := got["_wormhole_session"]
		require.NotNil(t, session)
		assert.Equal(t, "s", session.Value)
		assert.Equal(t, "/", session.Path)
		assert.Equal(t, 43200, session.MaxAge)
		assert.Empty(t, session.Domain, "session cookie must be host-only")
		assert.True(t, session.HttpOnly)
		assert.True(t, session.Secure)
		assert.Equal(t, http.SameSiteLaxMode, session.SameSite)

		binding := got[bindingCookie]
		require.NotNil(t, binding)
		assert.Equal(t, paths.CallbackPrefix, binding.Path)
		assert.Negative(t, binding.MaxAge, "binding cookie must be expired")
	})

	t.Run("omits Secure on plain http", func(t *testing.T) {
		rec := serveCallback(t, &stubLedger{}, oauthapi.SessionStoreCookie, callback{host: "foo.example.com", scheme: "http"})

		require.Equal(t, http.StatusFound, rec.Code)
		assert.False(t, setCookies(rec)["_wormhole_session"].Secure)
	})

	t.Run("target on another host falls back to root", func(t *testing.T) {
		stub := &stubLedger{redeemResp: RedeemResponse{SessionCookie: "s", TargetURL: "https://evil.example.com/"}}

		rec := serveCallback(t, stub, oauthapi.SessionStoreCookie, callback{host: "foo.example.com"})

		require.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, "/", rec.Header().Get("Location"))
	})

	t.Run("rejects an unsafe cookie value", func(t *testing.T) {
		stub := &stubLedger{redeemResp: RedeemResponse{SessionCookie: "a;b", TargetURL: "https://foo.example.com/"}}

		rec := serveCallback(t, stub, oauthapi.SessionStoreCookie, callback{host: "foo.example.com"})

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.NotContains(t, setCookies(rec), "_wormhole_session")
		assert.Contains(t, setCookies(rec), bindingCookie, "the flow was consumed")
	})

	ledgerErrors := map[string]struct {
		err           error
		status        int
		expireBinding bool
	}{
		"invalid request":  {ErrInvalidRequest, http.StatusBadRequest, true},
		"flow unavailable": {ErrFlowUnavailable, http.StatusUnauthorized, true},
		"binding mismatch": {ErrBindingMismatch, http.StatusUnauthorized, true},
		"store failure":    {errors.New("boom"), http.StatusInternalServerError, false},
	}

	for name, tc := range ledgerErrors {
		t.Run(name, func(t *testing.T) {
			rec := serveCallback(t, &stubLedger{redeemErr: tc.err}, oauthapi.SessionStoreCookie, callback{
				host:    "foo.example.com",
				cookies: []string{bindingCookie + "=secret"},
			})

			assert.Equal(t, tc.status, rec.Code)
			assert.Equal(t, tc.expireBinding, setCookies(rec)[bindingCookie] != nil)
			assert.NotContains(t, setCookies(rec), "_wormhole_session")
		})
	}
}

func Test_callback_redeem_sessionStore(t *testing.T) {
	large := strings.Repeat("x", oauthapi.CookieChunkSize+1)

	redeem := func(t *testing.T, store oauthapi.SessionStore, session string, cookies ...string) *httptest.ResponseRecorder {
		t.Helper()

		stub := &stubLedger{redeemResp: RedeemResponse{SessionCookie: session, TargetURL: "https://foo.example.com/"}}

		return serveCallback(t, stub, store, callback{host: "foo.example.com", cookies: cookies})
	}

	t.Run("cookie store splits a large session into chunks", func(t *testing.T) {
		rec := redeem(t, oauthapi.SessionStoreCookie, large)

		require.Equal(t, http.StatusFound, rec.Code)

		got := setCookies(rec)
		assert.Equal(t, large[:oauthapi.CookieChunkSize], got["_wormhole_session_0"].Value)
		assert.Equal(t, "x", got["_wormhole_session_1"].Value)
		assert.NotContains(t, got, "_wormhole_session")
	})

	t.Run("surplus chunks and stale unsplit cookie are expired", func(t *testing.T) {
		rec := redeem(t, oauthapi.SessionStoreCookie, "small",
			"_wormhole_session_0=a; _wormhole_session_1=b; _wormhole_session_x=keep; other=1")

		require.Equal(t, http.StatusFound, rec.Code)

		got := setCookies(rec)
		assert.Equal(t, "small", got["_wormhole_session"].Value)
		assert.Negative(t, got["_wormhole_session_0"].MaxAge)
		assert.Negative(t, got["_wormhole_session_1"].MaxAge)
		assert.NotContains(t, got, "_wormhole_session_x")
		assert.NotContains(t, got, "other")
	})

	t.Run("redis store rejects a session too large for one cookie", func(t *testing.T) {
		rec := redeem(t, oauthapi.SessionStoreRedis, large)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.NotContains(t, setCookies(rec), "_wormhole_session_0")
	})
}
