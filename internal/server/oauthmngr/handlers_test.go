package oauthmngr

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/paths"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr/ledger"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr/oauthapi"
	"github.com/llnl/wormhole-holepunch/internal/server"
	"github.com/llnl/wormhole-holepunch/test/mocks/mock_oauthmngr"
)

var (
	ll       = logs.InitializeDiscard()
	redeemed = ledger.RedeemResponse{SessionHandle: testHandle, TargetURL: "https://foo.example.com/app"}
)

const (
	testNonce      = "AAAAAAAAAAAAAAAAAAAAAA"
	testRedeemCode = "BBBBBBBBBBBBBBBBBBBBBA"
	testHandle     = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA"
)

// newLedger returns a strict mock: any ledger call a test did not expect fails it.
func newLedger(t *testing.T) *mock_oauthmngr.MockLedger {
	t.Helper()

	return mock_oauthmngr.NewMockLedger(gomock.NewController(t))
}

func captureRequest(sessionCookie string) ledger.CaptureRequest {
	return ledger.CaptureRequest{
		Nonce:         testNonce,
		Authority:     testAuthDomain,
		SessionCookie: sessionCookie,
		AuthProof:     "auth-proof",
	}
}

func callbackConfig(store oauthapi.SessionStore) CallbackConfig {
	return CallbackConfig{
		AuthDomain:          testAuthDomain,
		ProxyCookieName:     "_oauth2_proxy",
		ProxySessionStore:   store,
		SessionCookieName:   "_wormhole_session",
		SessionCookieMaxAge: 43200,
		// The handler tests assert on the short cookie names, matching a plain-HTTP
		// development deployment where __Host- cookies cannot be issued.
		AllowInsecureCookieNames: true,
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
	headers http.Header
}

func serveCallback(t *testing.T, l ledger.Ledger, store oauthapi.SessionStore, c callback) *httptest.ResponseRecorder {
	t.Helper()

	cfg := callbackConfig(store)
	require.NoError(t, cfg.validate())

	d := &data{ll: ll, flows: l, cfg: cfg}

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
	for key, values := range c.headers {
		req.Header[key] = values
	}
	if !c.noEnvoy {
		req.Header.Set(keys.WormholeHostHeader, c.host)
		req.Header.Set(keys.WormholeSchemeHeader, c.scheme)
	}

	for _, v := range c.cookies {
		req.Header.Add(keys.CookieHeader, v)
	}

	rec := httptest.NewRecorder()
	server.LoggingMiddleware(ll, http.HandlerFunc(d.callbackHandler)).ServeHTTP(rec, req)

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

//

func Test_CallbackConfig_validate(t *testing.T) {
	require.NoError(t, callbackConfig(oauthapi.SessionStoreCookie).validate())

	// Outside development only the Holepunch session cookie requires the __Host- prefix.
	prod := callbackConfig(oauthapi.SessionStoreCookie)
	prod.AllowInsecureCookieNames = false
	prod.SessionCookieName = oauthapi.HostPrefix + "wormhole_session"
	require.NoError(t, prod.validate())

	prod.ProxyCookieName = oauthapi.HostPrefix + "_oauth2_proxy"
	require.NoError(t, prod.validate())

	invalid := map[string]func(*CallbackConfig){
		"missing auth domain":     func(c *CallbackConfig) { c.AuthDomain = "" },
		"invalid proxy cookie":    func(c *CallbackConfig) { c.ProxyCookieName = "bad;name" },
		"invalid session cookie":  func(c *CallbackConfig) { c.SessionCookieName = "" },
		"non-positive max age":    func(c *CallbackConfig) { c.SessionCookieMaxAge = 0 },
		"unsupported store":       func(c *CallbackConfig) { c.ProxySessionStore = "memcached" },
		"empty store is rejected": func(c *CallbackConfig) { c.ProxySessionStore = "" },
		"session cookie needs __Host- in prod": func(c *CallbackConfig) {
			c.AllowInsecureCookieNames = false
		},
	}

	for name, mutate := range invalid {
		t.Run(name, func(t *testing.T) {
			cfg := callbackConfig(oauthapi.SessionStoreCookie)
			mutate(&cfg)

			require.Error(t, cfg.validate())
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
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			rec := serveCallback(t, newLedger(t), oauthapi.SessionStoreCookie, tc.c)

			assert.Equal(t, tc.status, rec.Code)
		})
	}
}

func Test_callback_CORS(t *testing.T) {
	const origin = "https://" + testAuthDomain

	t.Run("browser preflights for both headers", func(t *testing.T) {
		for _, header := range []string{keys.WormholeOAuthProofHeader, keys.WormholeOAuthCodeHeader} {
			t.Run(header, func(t *testing.T) {
				c := callback{
					method: http.MethodOptions,
					host:   "foo.example.com",
					headers: http.Header{
						http.CanonicalHeaderKey(keys.OriginHeader):                      {origin},
						http.CanonicalHeaderKey(keys.SecFetchSiteHeader):                {"same-site"},
						http.CanonicalHeaderKey(keys.AccessControlRequestMethodHeader):  {http.MethodPost},
						http.CanonicalHeaderKey(keys.AccessControlRequestHeadersHeader): {header},
					},
				}
				rec := serveCallback(t, newLedger(t), oauthapi.SessionStoreCookie, c)

				require.Equal(t, http.StatusNoContent, rec.Code)
				assert.Equal(t, origin, rec.Header().Get(keys.AccessControlAllowOriginHeader))
				assert.Equal(t, "true", rec.Header().Get(keys.AccessControlAllowCredentialsHeader))
				assert.Equal(t, http.MethodPost, rec.Header().Get(keys.AccessControlAllowMethodsHeader))
				assert.Equal(t, http.CanonicalHeaderKey(header), rec.Header().Get(keys.AccessControlAllowHeadersHeader))
			})
		}
	})

	t.Run("early rejections include CORS headers only for the auth origin", func(t *testing.T) {
		for name, tc := range map[string]struct {
			c      callback
			status int
		}{
			"missing nonce": {callback{method: http.MethodPost, path: paths.CallbackPrefix, host: "foo.example.com"},
				http.StatusBadRequest},
			"invalid nonce": {callback{method: http.MethodPost, path: paths.CallbackPrefix + "?nonce=bad", host: "foo.example.com"},
				http.StatusBadRequest},
			"missing forwarded host": {callback{method: http.MethodPost, noEnvoy: true},
				http.StatusInternalServerError},
			"invalid scheme": {callback{method: http.MethodPost, host: "foo.example.com", scheme: "http"},
				http.StatusBadRequest},
			"invalid method": {callback{method: http.MethodPut, host: "foo.example.com"},
				http.StatusMethodNotAllowed},
		} {
			t.Run(name, func(t *testing.T) {
				for _, testOrigin := range []string{origin, "https://sibling.example.com"} {
					c := tc.c
					c.headers = http.Header{http.CanonicalHeaderKey(keys.OriginHeader): {testOrigin}}
					rec := serveCallback(t, newLedger(t), oauthapi.SessionStoreCookie, c)

					assert.Equal(t, tc.status, rec.Code)
					assert.Contains(t, rec.Header().Values(keys.VaryHeader), http.CanonicalHeaderKey(keys.OriginHeader))
					if testOrigin == origin {
						assert.Equal(t, origin, rec.Header().Get(keys.AccessControlAllowOriginHeader))
						assert.Equal(t, "true", rec.Header().Get(keys.AccessControlAllowCredentialsHeader))
					} else {
						assert.Empty(t, rec.Header().Get(keys.AccessControlAllowOriginHeader))
						assert.Empty(t, rec.Header().Get(keys.AccessControlAllowCredentialsHeader))
					}
				}
			})
		}
	})
}

func Test_callback_capture(t *testing.T) {
	complete := func(t *testing.T, flows ledger.Ledger, store oauthapi.SessionStore, cookieHeaders ...string) *httptest.ResponseRecorder {
		t.Helper()
		return serveCallback(t, flows, store, callback{
			method: http.MethodPost, host: testAuthDomain,
			headers: http.Header{http.CanonicalHeaderKey(keys.WormholeOAuthProofHeader): {"complete"}, http.CanonicalHeaderKey(keys.SecFetchSiteHeader): {"same-origin"}},
			cookies: append(cookieHeaders, oauthapi.AuthProofCookiePrefix+testNonce+"=auth-proof"),
		})
	}
	t.Run("captures the session and returns only the redemption code", func(t *testing.T) {
		flows := newLedger(t)
		flows.EXPECT().Capture(gomock.Any(), captureRequest("proxy-session")).
			Return(ledger.CaptureResponse{TargetSubdomain: "foo.example.com", RedeemCode: testRedeemCode}, nil)

		rec := complete(t, flows, oauthapi.SessionStoreCookie, "a=1", "_oauth2_proxy=proxy-session")

		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, testRedeemCode, rec.Body.String(), "no URL for the target host to navigate to")
		assert.Equal(t, "no-store", rec.Header().Get(keys.CacheControlHeader))
		assert.Equal(t, "no-referrer", rec.Header().Get(keys.ReferrerPolicyHeader))
		require.NotNil(t, setCookies(rec)[oauthapi.AuthProofCookiePrefix+testNonce])
		assert.Negative(t, setCookies(rec)[oauthapi.AuthProofCookiePrefix+testNonce].MaxAge)
	})

	t.Run("captures an unprefixed proxy cookie in production", func(t *testing.T) {
		cfg := callbackConfig(oauthapi.SessionStoreCookie)
		cfg.AllowInsecureCookieNames = false
		cfg.SessionCookieName = oauthapi.HostPrefix + "wormhole_session"
		require.NoError(t, cfg.validate())

		flows := newLedger(t)
		flows.EXPECT().Capture(gomock.Any(), captureRequest("proxy-session")).
			Return(ledger.CaptureResponse{TargetSubdomain: "foo.example.com", RedeemCode: testRedeemCode}, nil)

		d := &data{ll: ll, flows: flows, cfg: cfg}
		req := httptest.NewRequest(http.MethodPost, paths.CallbackPrefix+"?nonce="+testNonce, nil)
		req.Header.Set(keys.WormholeHostHeader, testAuthDomain)
		req.Header.Set(keys.WormholeSchemeHeader, "https")
		req.Header.Set(keys.SecFetchSiteHeader, "same-origin")
		req.Header.Set(keys.WormholeOAuthProofHeader, "complete")
		req.AddCookie(&http.Cookie{Name: "_oauth2_proxy", Value: "proxy-session"})
		req.AddCookie(&http.Cookie{Name: oauthapi.AuthProofCookiePrefix + testNonce, Value: "auth-proof"})

		rec := httptest.NewRecorder()
		server.LoggingMiddleware(ll, http.HandlerFunc(d.callbackHandler)).ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, testRedeemCode, rec.Body.String())
	})

	t.Run("missing oauth2-proxy cookie", func(t *testing.T) {
		rec := complete(t, newLedger(t), oauthapi.SessionStoreCookie)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("cookie store joins oauth2-proxy chunks", func(t *testing.T) {
		flows := newLedger(t)
		flows.EXPECT().Capture(gomock.Any(), captureRequest("abcdef")).
			Return(ledger.CaptureResponse{TargetSubdomain: "foo.example.com", RedeemCode: testRedeemCode}, nil)

		rec := complete(t, flows, oauthapi.SessionStoreCookie, "_oauth2_proxy_0=abc", "_oauth2_proxy_1=def")

		require.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("redis store rejects chunks as a misconfiguration", func(t *testing.T) {
		rec := complete(t, newLedger(t), oauthapi.SessionStoreRedis, "_oauth2_proxy_0=abc")

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	ledgerErrors := map[string]struct {
		err    error
		status int
	}{
		"invalid request":  {ledger.ErrInvalidRequest, http.StatusBadRequest},
		"flow unavailable": {ledger.ErrFlowUnavailable, http.StatusUnauthorized},
		"binding mismatch": {ledger.ErrBindingMismatch, http.StatusUnauthorized},
		"store failure":    {errors.New("boom"), http.StatusInternalServerError},
	}

	for name, tc := range ledgerErrors {
		t.Run(name, func(t *testing.T) {
			flows := newLedger(t)
			flows.EXPECT().Capture(gomock.Any(), captureRequest("proxy-session")).Return(ledger.CaptureResponse{}, tc.err)

			rec := complete(t, flows, oauthapi.SessionStoreCookie, "_oauth2_proxy=proxy-session")

			assert.Equal(t, tc.status, rec.Code)
			assert.Empty(t, rec.Header().Get(keys.LocationHeader))
		})
	}
}

func Test_callback_rejectsFailureReports(t *testing.T) {
	d := &data{ll: ll, flows: newLedger(t), cfg: callbackConfig(oauthapi.SessionStoreCookie)}

	req := httptest.NewRequest(http.MethodPost, paths.CallbackPrefix+"?nonce="+testNonce,
		strings.NewReader(`{"step":"redeem","status":401,"error":"HTTP 401"}`))
	req.Header.Set(keys.WormholeHostHeader, testAuthDomain)
	req.Header.Set(keys.WormholeSchemeHeader, "https")
	req.Header.Set(keys.SecFetchSiteHeader, "same-origin")
	req.Header.Set(keys.WormholeOAuthProofHeader, "failed")

	rec := httptest.NewRecorder()
	d.callbackHandler(rec, req.WithContext(logs.NewContext(req.Context(), ll)))

	assert.Equal(t, http.StatusForbidden, rec.Code, "unauthenticated failure reports are not accepted")
}

func Test_callback_authorizeCapture(t *testing.T) {
	headers := http.Header{
		http.CanonicalHeaderKey(keys.OriginHeader):                      {"https://" + testAuthDomain},
		http.CanonicalHeaderKey(keys.SecFetchSiteHeader):                {"same-site"},
		http.CanonicalHeaderKey(keys.AccessControlRequestMethodHeader):  {"POST"},
		http.CanonicalHeaderKey(keys.AccessControlRequestHeadersHeader): {keys.WormholeOAuthProofHeader},
		http.CanonicalHeaderKey(keys.WormholeOAuthProofHeader):          {"challenge"},
	}
	flows := newLedger(t)
	c := callback{method: http.MethodOptions, host: "foo.example.com", headers: headers}
	rec := serveCallback(t, flows, oauthapi.SessionStoreCookie, c)
	require.Equal(t, http.StatusNoContent, rec.Code, "preflight does not change flow state")
	assert.Equal(t, headers.Get(keys.OriginHeader), rec.Header().Get(keys.AccessControlAllowOriginHeader))
	assert.Equal(t, "true", rec.Header().Get(keys.AccessControlAllowCredentialsHeader))
	assert.Equal(t, http.CanonicalHeaderKey(keys.WormholeOAuthProofHeader), rec.Header().Get(keys.AccessControlAllowHeadersHeader))

	c.method = http.MethodPost
	rec = serveCallback(t, flows, oauthapi.SessionStoreCookie, c)
	require.Equal(t, http.StatusUnauthorized, rec.Code, "a different browser cannot authorize without the app cookie")

	c.cookies = []string{oauthapi.BindingCookieName(testNonce) + "=app-proof"}
	c.headers.Set(keys.OriginHeader, "https://sibling.example.com")
	rec = serveCallback(t, flows, oauthapi.SessionStoreCookie, c)
	require.Equal(t, http.StatusForbidden, rec.Code)
	assert.Empty(t, rec.Header().Get(keys.AccessControlAllowOriginHeader))

	c.headers.Set(keys.OriginHeader, "https://"+testAuthDomain)
	c.headers.Set(keys.SecFetchSiteHeader, "cross-site")
	rec = serveCallback(t, flows, oauthapi.SessionStoreCookie, c)
	require.Equal(t, http.StatusForbidden, rec.Code)

	c.headers.Set(keys.SecFetchSiteHeader, "same-site")
	flows.EXPECT().AuthorizeCapture(gomock.Any(), ledger.AuthorizeRequest{
		Nonce: testNonce, Authority: "foo.example.com", BindingSecret: "app-proof", Challenge: "challenge",
	}).Return(nil)
	rec = serveCallback(t, flows, oauthapi.SessionStoreCookie, c)
	require.Equal(t, http.StatusNoContent, rec.Code)
}

// redeemCallback is the auth page's credentialed redemption fetch to the target host.
func redeemCallback(cookies ...string) callback {
	return callback{
		method: http.MethodPost,
		host:   "foo.example.com",
		headers: http.Header{
			http.CanonicalHeaderKey(keys.OriginHeader):            {"https://" + testAuthDomain},
			http.CanonicalHeaderKey(keys.SecFetchSiteHeader):      {"same-site"},
			http.CanonicalHeaderKey(keys.WormholeOAuthCodeHeader): {testRedeemCode},
		},
		cookies: cookies,
	}
}

func Test_callback_redeem(t *testing.T) {
	bindingCookie := oauthapi.BindingCookieName(testNonce)

	t.Run("navigating to the target callback cannot redeem, even with a code", func(t *testing.T) {
		rec := serveCallback(t, newLedger(t), oauthapi.SessionStoreCookie, callback{
			host: "foo.example.com", path: paths.CallbackPrefix + "?nonce=" + testNonce + "&code=" + testRedeemCode,
			cookies: []string{bindingCookie + "=secret"},
		})

		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
		assert.Equal(t, "POST, OPTIONS", rec.Header().Get(keys.AllowHeader))
		assert.Empty(t, setCookies(rec))
	})

	t.Run("issues the host session cookie and returns the target", func(t *testing.T) {
		flows := newLedger(t)
		flows.EXPECT().Redeem(gomock.Any(), ledger.RedeemRequest{
			Nonce:         testNonce,
			Authority:     "foo.example.com",
			BindingSecret: "secret",
			Code:          testRedeemCode,
		}).Return(redeemed, nil)

		rec := serveCallback(t, flows, oauthapi.SessionStoreCookie, redeemCallback(bindingCookie+"=secret"))

		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "https://foo.example.com/app", rec.Body.String())
		assert.Empty(t, rec.Header().Get(keys.LocationHeader), "the auth page navigates, not the redirect")
		assert.Equal(t, "https://"+testAuthDomain, rec.Header().Get(keys.AccessControlAllowOriginHeader))
		assert.Equal(t, "true", rec.Header().Get(keys.AccessControlAllowCredentialsHeader))
		assert.Equal(t, "no-store", rec.Header().Get(keys.CacheControlHeader))

		got := setCookies(rec)
		require.Len(t, got, 2)

		session := got["_wormhole_session"]
		require.NotNil(t, session)
		assert.Equal(t, testHandle, session.Value, "the cookie holds the host session handle")
		assert.Equal(t, "/", session.Path)
		assert.Equal(t, 43200, session.MaxAge)
		assert.Empty(t, session.Domain, "session cookie must be host-only")
		assert.True(t, session.HttpOnly)
		assert.True(t, session.Secure)
		assert.Equal(t, http.SameSiteLaxMode, session.SameSite)

		binding := got[bindingCookie]
		require.NotNil(t, binding)
		assert.Equal(t, "/", binding.Path)
		assert.Negative(t, binding.MaxAge, "binding cookie must be expired")
	})

	t.Run("preflight admits only the code header from the auth origin", func(t *testing.T) {
		c := redeemCallback()
		c.method = http.MethodOptions
		c.headers.Set(keys.AccessControlRequestMethodHeader, http.MethodPost)
		c.headers.Set(keys.AccessControlRequestHeadersHeader, strings.ToLower(keys.WormholeOAuthCodeHeader))

		flows := newLedger(t)
		rec := serveCallback(t, flows, oauthapi.SessionStoreCookie, c)
		require.Equal(t, http.StatusNoContent, rec.Code, "preflight does not change flow state")
		assert.Equal(t, http.CanonicalHeaderKey(keys.WormholeOAuthCodeHeader), rec.Header().Get(keys.AccessControlAllowHeadersHeader))

		c.headers.Set(keys.AccessControlRequestHeadersHeader, strings.ToLower(keys.WormholeOAuthCodeHeader)+", x-other")
		rec = serveCallback(t, flows, oauthapi.SessionStoreCookie, c)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("only the auth page may redeem", func(t *testing.T) {
		for name, tc := range map[string]struct {
			mutate func(http.Header)
			// readable reports whether the requester may read the rejection: only the auth
			// origin, so the proof page can report the status instead of an opaque error.
			readable bool
		}{
			"sibling origin":   {func(h http.Header) { h.Set(keys.OriginHeader, "https://bar.example.com") }, false},
			"target origin":    {func(h http.Header) { h.Set(keys.OriginHeader, "https://foo.example.com") }, false},
			"no fetch headers": {func(h http.Header) { h.Del(keys.OriginHeader); h.Del(keys.SecFetchSiteHeader) }, false},
			"cross-site fetch": {func(h http.Header) { h.Set(keys.SecFetchSiteHeader, "cross-site") }, true},
		} {
			t.Run(name, func(t *testing.T) {
				c := redeemCallback(bindingCookie + "=secret")
				tc.mutate(c.headers)

				rec := serveCallback(t, newLedger(t), oauthapi.SessionStoreCookie, c)

				assert.Equal(t, http.StatusForbidden, rec.Code)
				assert.Equal(t, tc.readable, rec.Header().Get(keys.AccessControlAllowOriginHeader) == "https://"+testAuthDomain)
				assert.Empty(t, setCookies(rec))
			})
		}
	})

	t.Run("malformed or repeated codes are rejected without consuming the flow", func(t *testing.T) {
		for name, codes := range map[string][]string{
			"malformed": {"bad"},
			"repeated":  {testRedeemCode, testRedeemCode},
		} {
			t.Run(name, func(t *testing.T) {
				c := redeemCallback(bindingCookie + "=secret")
				c.headers[http.CanonicalHeaderKey(keys.WormholeOAuthCodeHeader)] = codes

				rec := serveCallback(t, newLedger(t), oauthapi.SessionStoreCookie, c)

				assert.Equal(t, http.StatusBadRequest, rec.Code)
			})
		}
	})

	t.Run("rejects plain HTTP", func(t *testing.T) {
		c := redeemCallback()
		c.scheme = "http"
		rec := serveCallback(t, newLedger(t), oauthapi.SessionStoreCookie, c)

		require.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Empty(t, setCookies(rec))
	})

	t.Run("target on another host falls back to root", func(t *testing.T) {
		flows := newLedger(t)
		flows.EXPECT().Redeem(gomock.Any(), gomock.Any()).
			Return(ledger.RedeemResponse{SessionHandle: testHandle, TargetURL: "https://evil.example.com/"}, nil)

		rec := serveCallback(t, flows, oauthapi.SessionStoreCookie, redeemCallback())

		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "/", rec.Body.String())
	})

	t.Run("rejects an unsafe cookie value", func(t *testing.T) {
		flows := newLedger(t)
		flows.EXPECT().Redeem(gomock.Any(), gomock.Any()).
			Return(ledger.RedeemResponse{SessionHandle: "a;b", TargetURL: "https://foo.example.com/"}, nil)

		rec := serveCallback(t, flows, oauthapi.SessionStoreCookie, redeemCallback())

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.NotContains(t, setCookies(rec), "_wormhole_session")
		assert.Contains(t, setCookies(rec), bindingCookie, "the flow was consumed")
	})

	t.Run("expires session chunks left by earlier releases", func(t *testing.T) {
		flows := newLedger(t)
		flows.EXPECT().Redeem(gomock.Any(), gomock.Any()).Return(redeemed, nil)

		rec := serveCallback(t, flows, oauthapi.SessionStoreCookie, redeemCallback(
			"_wormhole_session=old; _wormhole_session_0=a; _wormhole_session_1=b; _wormhole_session_x=keep; other=1"))

		require.Equal(t, http.StatusOK, rec.Code)

		got := setCookies(rec)
		assert.Equal(t, testHandle, got["_wormhole_session"].Value)
		assert.Negative(t, got["_wormhole_session_0"].MaxAge)
		assert.Negative(t, got["_wormhole_session_1"].MaxAge)
		assert.NotContains(t, got, "_wormhole_session_x")
		assert.NotContains(t, got, "other")
	})

	ledgerErrors := map[string]struct {
		err           error
		status        int
		expireBinding bool
	}{
		"invalid request":  {ledger.ErrInvalidRequest, http.StatusBadRequest, true},
		"flow unavailable": {ledger.ErrFlowUnavailable, http.StatusUnauthorized, true},
		"binding mismatch": {ledger.ErrBindingMismatch, http.StatusUnauthorized, true},
		"store failure":    {errors.New("boom"), http.StatusInternalServerError, false},
	}

	for name, tc := range ledgerErrors {
		t.Run(name, func(t *testing.T) {
			flows := newLedger(t)
			flows.EXPECT().Redeem(gomock.Any(), gomock.Any()).Return(ledger.RedeemResponse{}, tc.err)

			rec := serveCallback(t, flows, oauthapi.SessionStoreCookie, redeemCallback(bindingCookie+"=secret"))

			assert.Equal(t, tc.status, rec.Code)
			assert.Equal(t, tc.expireBinding, setCookies(rec)[bindingCookie] != nil)
			assert.NotContains(t, setCookies(rec), "_wormhole_session")
		})
	}
}

const testAuthDomain = "auth.example.com"

// ledgerServer returns the handler exactly as API serves it, middleware included.
func ledgerServer(t *testing.T, flows ledger.Ledger) http.Handler {
	t.Helper()

	ll := logs.InitializeDiscard()

	d := &data{ll: ll, flows: flows, cfg: callbackConfig(oauthapi.SessionStoreCookie)}
	mux := d.oauthHandlers()

	return server.Configuration{Address: ":0"}.NewHTTPServer(ll, mux).Handler
}

func Test_data_oauthHandlers(t *testing.T) {
	serve := func(method, path string) int {
		rec := httptest.NewRecorder()
		ledgerServer(t, newLedger(t)).ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader("")))

		return rec.Code
	}

	t.Run("callback is served by the ledger", func(t *testing.T) {
		flows := newLedger(t)
		flows.EXPECT().BeginCapture(gomock.Any(), testNonce).Return(
			ledger.CaptureStart{TargetAuthority: "foo.example.com", AuthProof: "auth-proof", Challenge: "challenge"}, nil)

		req := httptest.NewRequest(http.MethodGet, paths.CallbackPrefix+"?nonce="+testNonce, nil)
		req.Header.Set(keys.WormholeHostHeader, testAuthDomain)
		req.Header.Set(keys.WormholeSchemeHeader, "https")
		req.Header.Set(keys.CookieHeader, "_oauth2_proxy=session")

		rec := httptest.NewRecorder()
		ledgerServer(t, flows).ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "Finishing sign-in")
		assert.Contains(t, rec.Body.String(), `"`+http.CanonicalHeaderKey(keys.WormholeOAuthProofHeader)+`": "challenge"`)
		assert.Contains(t, rec.Body.String(), `"`+http.CanonicalHeaderKey(keys.WormholeOAuthProofHeader)+`": "complete"`)
		assert.Contains(t, rec.Body.String(), `{"`+http.CanonicalHeaderKey(keys.WormholeOAuthCodeHeader)+`": code}, "include"`,
			"the code is redeemed by a credentialed fetch from the auth page")
		assert.NotContains(t, rec.Body.String(), "location.replace(code)",
			"the code is never navigated to on the target host")
		assert.NotContains(t, rec.Body.String(), `": "failed"`, "failures are not reported to the auth host")
		proof := setCookies(rec)[oauthapi.AuthProofCookiePrefix+testNonce]
		require.NotNil(t, proof)
		assert.True(t, proof.Secure)
		assert.True(t, proof.HttpOnly)
		assert.Empty(t, proof.Domain)
		assert.Equal(t, "/", proof.Path)
	})

	t.Run("callback rejects unrelated methods", func(t *testing.T) {
		assert.Equal(t, http.StatusMethodNotAllowed, serve(http.MethodPut, paths.CallbackPrefix+"?nonce=n"))
	})

	t.Run("callback sub-paths are not served", func(t *testing.T) {
		assert.Equal(t, http.StatusNotFound, serve(http.MethodGet, paths.CallbackPrefix+"/x?nonce=n"))
	})

	t.Run("health and version", func(t *testing.T) {
		assert.Equal(t, http.StatusOK, serve(http.MethodGet, paths.HealthPath))
		assert.Equal(t, http.StatusOK, serve(http.MethodGet, paths.VersionPath))
	})

	t.Run("admin endpoints are not exposed", func(t *testing.T) {
		assert.Equal(t, http.StatusNotFound, serve(http.MethodGet, paths.ControlsPath))
		assert.Equal(t, http.StatusNotFound, serve(http.MethodPost, paths.InvalidateWebhookPath))
	})
}

func Test_API_rejectsInvalidCallbackConfig(t *testing.T) {
	cfg := callbackConfig(oauthapi.SessionStoreCookie)
	cfg.AuthDomain = ""

	// Validation fails before the listener starts, so no server is bound.
	err := StartServer(context.Background(), server.Configuration{Address: ":0"}, logs.InitializeDiscard(), newLedger(t), cfg)
	require.Error(t, err)
}
