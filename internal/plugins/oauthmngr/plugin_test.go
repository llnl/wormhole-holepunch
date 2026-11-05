package oauthmngr

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm/proxytest"
	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/llnl/wormhole-holepunch/internal/ctls/paths"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr/oauthapi"
)

const testNonce = "AAAAAAAAAAAAAAAAAAAAAA"

func testConfig() oauthapi.PluginConfig {
	return oauthapi.PluginConfig{
		AuthDomain:          "auth.example.com",
		ProxyCookieName:     "_oauth2_proxy",
		SessionCookieName:   "_wormhole_session",
		SessionCookieMaxAge: 43200,
		ProxySessionStore:   oauthapi.SessionStoreCookie,
		LedgerCluster:       "oauthmngr_ledger",
		LedgerTimeoutMs:     2000,
	}
}

type harness struct {
	host proxytest.HostEmulator
	id   uint32
}

// newHarness starts the plugin with the configuration and a client at 10.0.0.1, then opens
// a single HTTP stream.
func newHarness(t *testing.T, cfg any, opts ...func(*proxytest.EmulatorOption)) harness {
	t.Helper()

	raw, err := json.Marshal(cfg)
	require.NoError(t, err)

	opt := proxytest.NewEmulatorOption().
		WithVMContext(&vmContext{}).
		WithPluginConfiguration(raw).
		WithProperty([]string{"source", "address"}, []byte("10.0.0.1:51234"))

	for _, o := range opts {
		o(opt)
	}

	host, reset := proxytest.NewHostEmulator(opt)
	t.Cleanup(reset)

	require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())

	return harness{host: host, id: host.InitializeHttpContext()}
}

func requestHeaders(authority, path string, extra ...[2]string) [][2]string {
	return append([][2]string{
		{":method", "GET"},
		{":scheme", "https"},
		{":authority", authority},
		{":path", path},
	}, extra...)
}

func callbackPath(nonce string) string {
	return paths.CallbackPrefix + "?" + oauthapi.NonceParam + "=" + nonce
}

func header(headers [][2]string, name string) string {
	for _, h := range headers {
		if h[0] == name {
			return h[1]
		}
	}

	return ""
}

// callout returns the single pending ledger callout.
func (h harness) callout(t *testing.T) proxytest.HttpCalloutAttribute {
	t.Helper()

	attrs := h.host.GetCalloutAttributesFromContext(h.id)
	require.Len(t, attrs, 1)

	return attrs[0]
}

func (h harness) respond(t *testing.T, status string, body any) {
	t.Helper()

	raw, err := json.Marshal(body)
	require.NoError(t, err)

	h.host.CallOnHttpCallResponse(h.callout(t).CalloutID, [][2]string{{":status", status}}, nil, raw)
}

func (h harness) localResponse(t *testing.T) *proxytest.LocalHttpResponse {
	t.Helper()

	resp := h.host.GetSentLocalResponse(h.id)
	require.NotNil(t, resp, "a local reply must always be sent")
	assert.Equal(t, "no-store", header(resp.Headers, "cache-control"))
	assert.Equal(t, "no-referrer", header(resp.Headers, "referrer-policy"))

	return resp
}

func Test_parseConfig(t *testing.T) {
	t.Run("valid configuration", func(t *testing.T) {
		raw, _ := json.Marshal(testConfig())

		cfg, err := parseConfig(raw)

		require.NoError(t, err)
		assert.Equal(t, testConfig(), cfg)
	})

	t.Run("defaults ledger timeout", func(t *testing.T) {
		c := testConfig()
		c.LedgerTimeoutMs = 0
		raw, _ := json.Marshal(c)

		cfg, err := parseConfig(raw)

		require.NoError(t, err)
		assert.Equal(t, oauthapi.LedgerTimeoutMs, cfg.LedgerTimeoutMs)
	})

	t.Run("defaults session store to cookie", func(t *testing.T) {
		c := testConfig()
		c.ProxySessionStore = ""
		raw, _ := json.Marshal(c)

		cfg, err := parseConfig(raw)

		require.NoError(t, err)
		assert.Equal(t, oauthapi.SessionStoreCookie, cfg.ProxySessionStore)
	})

	invalid := map[string]func(*oauthapi.PluginConfig){
		"unknown session store":      func(c *oauthapi.PluginConfig) { c.ProxySessionStore = "memcached" },
		"missing auth domain":        func(c *oauthapi.PluginConfig) { c.AuthDomain = "" },
		"missing ledger cluster":     func(c *oauthapi.PluginConfig) { c.LedgerCluster = "" },
		"missing proxy cookie name":  func(c *oauthapi.PluginConfig) { c.ProxyCookieName = "" },
		"invalid session cookie":     func(c *oauthapi.PluginConfig) { c.SessionCookieName = "bad;name" },
		"zero max age":               func(c *oauthapi.PluginConfig) { c.SessionCookieMaxAge = 0 },
		"negative ledger timeout ms": func(c *oauthapi.PluginConfig) { c.LedgerTimeoutMs = -1 },
	}

	for name, mutate := range invalid {
		t.Run(name, func(t *testing.T) {
			c := testConfig()
			mutate(&c)
			raw, _ := json.Marshal(c)

			_, err := parseConfig(raw)

			require.Error(t, err)
		})
	}

	t.Run("empty", func(t *testing.T) {
		_, err := parseConfig(nil)
		require.Error(t, err)
	})

	t.Run("unknown fields", func(t *testing.T) {
		_, err := parseConfig([]byte(`{"auth_domain":"a","unexpected":true}`))
		require.Error(t, err)
	})
}

func Test_OnPluginStart_rejectsInvalidConfig(t *testing.T) {
	opt := proxytest.NewEmulatorOption().
		WithVMContext(&vmContext{}).
		WithPluginConfiguration([]byte(`{}`))

	host, reset := proxytest.NewHostEmulator(opt)
	defer reset()

	assert.Equal(t, types.OnPluginStartStatusFailed, host.StartPlugin())
}

func Test_rejectedRequests(t *testing.T) {
	tests := map[string]struct {
		headers [][2]string
		status  uint32
	}{
		"non-GET method": {
			headers: [][2]string{{":method", "POST"}, {":authority", "foo.example.com"}, {":path", callbackPath(testNonce)}},
			status:  405,
		},
		"different path": {
			headers: requestHeaders("foo.example.com", paths.CallbackPrefix+"/other?nonce="+testNonce),
			status:  404,
		},
		"missing nonce": {
			headers: requestHeaders("foo.example.com", paths.CallbackPrefix),
			status:  400,
		},
		"malformed nonce": {
			headers: requestHeaders("foo.example.com", callbackPath("abc")),
			status:  400,
		},
		"repeated nonce": {
			headers: requestHeaders("foo.example.com", callbackPath(testNonce)+"&nonce="+testNonce),
			status:  400,
		},
		"missing authority": {
			headers: [][2]string{{":method", "GET"}, {":path", callbackPath(testNonce)}},
			status:  400,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, testConfig())

			action := h.host.CallOnRequestHeaders(h.id, tc.headers, true)

			assert.Equal(t, types.ActionPause, action)
			assert.Equal(t, tc.status, h.localResponse(t).StatusCode)
			assert.Empty(t, h.host.GetCalloutAttributesFromContext(h.id))
		})
	}

	t.Run("missing client address", func(t *testing.T) {
		raw, _ := json.Marshal(testConfig())
		host, reset := proxytest.NewHostEmulator(
			proxytest.NewEmulatorOption().WithVMContext(&vmContext{}).WithPluginConfiguration(raw),
		)
		defer reset()

		require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())
		id := host.InitializeHttpContext()

		host.CallOnRequestHeaders(id, requestHeaders("foo.example.com", callbackPath(testNonce)), true)

		require.NotNil(t, host.GetSentLocalResponse(id))
		assert.Equal(t, uint32(500), host.GetSentLocalResponse(id).StatusCode)
	})
}

func Test_strip_nonce_from_path(t *testing.T) {
	h := newHarness(t, testConfig())

	h.host.CallOnRequestHeaders(h.id, requestHeaders("foo.example.com", callbackPath(testNonce)), true)

	assert.Equal(t, paths.CallbackPrefix, header(h.host.GetCurrentRequestHeaders(h.id), ":path"))
}

func Test_capture(t *testing.T) {
	authReq := func(extra ...[2]string) [][2]string {
		return requestHeaders("auth.example.com", callbackPath(testNonce), extra...)
	}
	withCookie := [2]string{"cookie", "other=1; _oauth2_proxy=proxy-session"}

	t.Run("missing oauth2-proxy cookie", func(t *testing.T) {
		h := newHarness(t, testConfig())

		h.host.CallOnRequestHeaders(h.id, authReq([2]string{"cookie", "other=1"}), true)

		assert.Equal(t, uint32(401), h.localResponse(t).StatusCode)
		assert.Empty(t, h.host.GetCalloutAttributesFromContext(h.id))
	})

	t.Run("dispatches capture to the ledger", func(t *testing.T) {
		h := newHarness(t, testConfig())

		action := h.host.CallOnRequestHeaders(h.id, authReq(withCookie), true)
		require.Equal(t, types.ActionPause, action)
		assert.Nil(t, h.host.GetSentLocalResponse(h.id), "waits for the ledger")

		c := h.callout(t)
		assert.Equal(t, "oauthmngr_ledger", c.Upstream)
		assert.Equal(t, "POST", header(c.Headers, ":method"))
		assert.Equal(t, paths.CapturePath, header(c.Headers, ":path"))
		assert.Equal(t, "application/json", header(c.Headers, "content-type"))

		var req oauthapi.CaptureRequest
		require.NoError(t, json.Unmarshal(c.Body, &req))
		assert.Equal(t, oauthapi.CaptureRequest{
			Nonce:         testNonce,
			ClientIP:      "10.0.0.1",
			Authority:     "auth.example.com",
			SessionCookie: "proxy-session",
		}, req)
	})

	t.Run("cookie split across multiple headers", func(t *testing.T) {
		h := newHarness(t, testConfig())

		h.host.CallOnRequestHeaders(h.id, authReq(
			[2]string{"cookie", "other=1"},
			[2]string{"cookie", "_oauth2_proxy=proxy-session"},
		), true)

		var req oauthapi.CaptureRequest
		require.NoError(t, json.Unmarshal(h.callout(t).Body, &req))
		assert.Equal(t, "proxy-session", req.SessionCookie)
	})

	t.Run("auth domain matched regardless of port", func(t *testing.T) {
		h := newHarness(t, testConfig())

		h.host.CallOnRequestHeaders(h.id,
			requestHeaders("auth.example.com:8443", callbackPath(testNonce), withCookie), true)

		assert.Equal(t, paths.CapturePath, header(h.callout(t).Headers, ":path"))
	})

	t.Run("redirects to the sub-domain callback", func(t *testing.T) {
		h := newHarness(t, testConfig())
		h.host.CallOnRequestHeaders(h.id, authReq(withCookie), true)

		callback := "https://foo.example.com" + callbackPath(testNonce)
		h.respond(t, "200", oauthapi.CaptureResponse{TargetSubdomain: "foo.example.com", CallbackURL: callback})

		resp := h.localResponse(t)
		assert.Equal(t, uint32(302), resp.StatusCode)
		assert.Equal(t, callback, header(resp.Headers, "location"))
		assert.Empty(t, header(resp.Headers, "set-cookie"))
	})

	t.Run("rejects a callback URL outside the callback route", func(t *testing.T) {
		h := newHarness(t, testConfig())
		h.host.CallOnRequestHeaders(h.id, authReq(withCookie), true)

		h.respond(t, "200", oauthapi.CaptureResponse{CallbackURL: "https://evil.example.com/"})

		assert.Equal(t, uint32(500), h.localResponse(t).StatusCode)
	})
}

func Test_redeem(t *testing.T) {
	subReq := func(scheme string) [][2]string {
		return [][2]string{
			{":method", "GET"},
			{":scheme", scheme},
			{":authority", "foo.example.com"},
			{":path", callbackPath(testNonce)},
			{"cookie", oauthapi.BindingCookieName(testNonce) + "=browser-proof"},
		}
	}

	t.Run("dispatches redeem to the ledger", func(t *testing.T) {
		h := newHarness(t, testConfig())

		h.host.CallOnRequestHeaders(h.id, subReq("https"), true)

		c := h.callout(t)
		assert.Equal(t, paths.RedeemPath, header(c.Headers, ":path"))

		var req oauthapi.RedeemRequest
		require.NoError(t, json.Unmarshal(c.Body, &req))
		assert.Equal(t, oauthapi.RedeemRequest{
			Nonce:         testNonce,
			ClientIP:      "10.0.0.1",
			Authority:     "foo.example.com",
			BindingSecret: "browser-proof",
		}, req)
	})

	t.Run("issues the session cookie and redirects to the target", func(t *testing.T) {
		h := newHarness(t, testConfig())
		h.host.CallOnRequestHeaders(h.id, subReq("https"), true)

		h.respond(t, "200", oauthapi.RedeemResponse{
			SessionCookie: "proxy|session=",
			TargetURL:     "https://foo.example.com/app?x=1",
		})

		resp := h.localResponse(t)
		assert.Equal(t, uint32(302), resp.StatusCode)
		assert.Equal(t, "https://foo.example.com/app?x=1", header(resp.Headers, "location"))
		assert.Equal(t,
			"_wormhole_session=proxy|session=; Path=/; Max-Age=43200; HttpOnly; Secure; SameSite=Lax",
			header(resp.Headers, "set-cookie"),
		)
		assert.Contains(t, allSetCookies(resp.Headers), oauthapi.BindingCookieName(testNonce)+"=; Path="+paths.CallbackPrefix+"; Max-Age=0; HttpOnly; Secure; SameSite=Lax")
	})

	t.Run("omits Secure on plain http", func(t *testing.T) {
		h := newHarness(t, testConfig())
		h.host.CallOnRequestHeaders(h.id, subReq("http"), true)

		h.respond(t, "200", oauthapi.RedeemResponse{SessionCookie: "s", TargetURL: "http://foo.example.com/"})

		assert.NotContains(t, header(h.localResponse(t).Headers, "set-cookie"), "Secure")
	})

	t.Run("target on another host falls back to root", func(t *testing.T) {
		h := newHarness(t, testConfig())
		h.host.CallOnRequestHeaders(h.id, subReq("https"), true)

		h.respond(t, "200", oauthapi.RedeemResponse{SessionCookie: "s", TargetURL: "https://bar.example.com/app"})

		assert.Equal(t, "/", header(h.localResponse(t).Headers, "location"))
	})

	t.Run("rejects an unsafe cookie value", func(t *testing.T) {
		h := newHarness(t, testConfig())
		h.host.CallOnRequestHeaders(h.id, subReq("https"), true)

		h.respond(t, "200", oauthapi.RedeemResponse{SessionCookie: "s; Domain=example.com", TargetURL: "https://foo.example.com/"})

		resp := h.localResponse(t)
		assert.Equal(t, uint32(500), resp.StatusCode)
		assert.Empty(t, setCookies(resp.Headers))
		assert.Equal(t, []string{
			oauthapi.BindingCookieName(testNonce) + "=; Path=" + paths.CallbackPrefix + "; Max-Age=0; HttpOnly; Secure; SameSite=Lax",
		}, allSetCookies(resp.Headers))
	})
}

func Test_ledgerFailures(t *testing.T) {
	tests := map[string]struct {
		status string
		want   uint32
	}{
		"malformed request": {status: "400", want: 400},
		"flow unavailable":  {status: "403", want: 401},
		"ledger error":      {status: "500", want: 500},
		"unexpected status": {status: "204", want: 500},
		"unparsable status": {status: "abc", want: 500},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, testConfig())
			h.host.CallOnRequestHeaders(h.id, requestHeaders("foo.example.com", callbackPath(testNonce)), true)

			h.host.CallOnHttpCallResponse(h.callout(t).CalloutID, [][2]string{{":status", tc.status}}, nil, nil)

			resp := h.localResponse(t)
			assert.Equal(t, tc.want, resp.StatusCode)
			assert.Empty(t, setCookies(resp.Headers))
			if tc.status == "400" || tc.status == "403" {
				assert.Equal(t, []string{
					oauthapi.BindingCookieName(testNonce) + "=; Path=" + paths.CallbackPrefix + "; Max-Age=0; HttpOnly; Secure; SameSite=Lax",
				}, allSetCookies(resp.Headers))
			} else {
				assert.Empty(t, allSetCookies(resp.Headers), "transient failures preserve the binding cookie")
			}
		})
	}

	t.Run("timeout or reset", func(t *testing.T) {
		h := newHarness(t, testConfig())
		h.host.CallOnRequestHeaders(h.id, requestHeaders("foo.example.com", callbackPath(testNonce)), true)

		h.host.CallOnHttpCallResponse(h.callout(t).CalloutID, nil, nil, nil)

		resp := h.localResponse(t)
		assert.Equal(t, uint32(500), resp.StatusCode)
		assert.Empty(t, allSetCookies(resp.Headers), "timeouts preserve the binding cookie for retry")
	})

	t.Run("undecodable success body", func(t *testing.T) {
		h := newHarness(t, testConfig())
		h.host.CallOnRequestHeaders(h.id, requestHeaders("foo.example.com", callbackPath(testNonce)), true)

		h.host.CallOnHttpCallResponse(h.callout(t).CalloutID, [][2]string{{":status", "200"}}, nil, []byte("{"))

		assert.Equal(t, uint32(500), h.localResponse(t).StatusCode)
	})
}

func Test_validCookie(t *testing.T) {
	assert.True(t, validCookieName("_wormhole_session"))
	assert.False(t, validCookieName(""))
	assert.False(t, validCookieName("a b"))
	assert.False(t, validCookieName("a=b"))

	assert.True(t, validCookieValue("abc|123=="))
	assert.False(t, validCookieValue(""))
	assert.False(t, validCookieValue("a;b"))
	assert.False(t, validCookieValue("a b"))
	assert.False(t, validCookieValue("a\r\nb"))
	assert.False(t, validCookieValue(`"a"`))
}

func redisConfig() oauthapi.PluginConfig {
	c := testConfig()
	c.ProxySessionStore = oauthapi.SessionStoreRedis

	return c
}

func setCookies(headers [][2]string) []string {
	out := make([]string, 0)

	for _, cookie := range allSetCookies(headers) {
		if !strings.HasPrefix(cookie, oauthapi.BindingCookiePrefix) {
			out = append(out, cookie)
		}
	}

	return out
}

func allSetCookies(headers [][2]string) []string {
	out := make([]string, 0)

	for _, h := range headers {
		if h[0] == "set-cookie" {
			out = append(out, h[1])
		}
	}

	return out
}

func Test_capture_sessionStore(t *testing.T) {
	chunked := [2]string{"cookie", "other=1; _oauth2_proxy_0=proxy-; _oauth2_proxy_1=session"}

	t.Run("cookie store joins oauth2-proxy chunks", func(t *testing.T) {
		h := newHarness(t, testConfig())

		h.host.CallOnRequestHeaders(h.id, requestHeaders("auth.example.com", callbackPath(testNonce), chunked), true)

		var req oauthapi.CaptureRequest
		require.NoError(t, json.Unmarshal(h.callout(t).Body, &req))
		assert.Equal(t, "proxy-session", req.SessionCookie)
	})

	t.Run("redis store reads the single cookie", func(t *testing.T) {
		h := newHarness(t, redisConfig())

		h.host.CallOnRequestHeaders(h.id, requestHeaders("auth.example.com", callbackPath(testNonce),
			[2]string{"cookie", "_oauth2_proxy=ticket"}), true)

		var req oauthapi.CaptureRequest
		require.NoError(t, json.Unmarshal(h.callout(t).Body, &req))
		assert.Equal(t, "ticket", req.SessionCookie)
	})

	t.Run("redis store rejects chunks as a misconfiguration", func(t *testing.T) {
		h := newHarness(t, redisConfig())

		h.host.CallOnRequestHeaders(h.id, requestHeaders("auth.example.com", callbackPath(testNonce), chunked), true)

		assert.Equal(t, uint32(500), h.localResponse(t).StatusCode)
		assert.Empty(t, h.host.GetCalloutAttributesFromContext(h.id))
	})
}

func Test_redeem_sessionStore(t *testing.T) {
	large := strings.Repeat("a", oauthapi.CookieChunkSize) + "tail"
	attrs := "; Path=/; Max-Age=43200; HttpOnly; Secure; SameSite=Lax"
	expired := "=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax"

	redeemWith := func(t *testing.T, cfg oauthapi.PluginConfig, cookieHeader, session string) *proxytest.LocalHttpResponse {
		t.Helper()

		h := newHarness(t, cfg)

		var extra [][2]string
		if cookieHeader != "" {
			extra = append(extra, [2]string{"cookie", cookieHeader})
		}

		h.host.CallOnRequestHeaders(h.id, requestHeaders("foo.example.com", callbackPath(testNonce), extra...), true)
		h.respond(t, "200", oauthapi.RedeemResponse{SessionCookie: session, TargetURL: "https://foo.example.com/app"})

		return h.localResponse(t)
	}

	t.Run("cookie store splits a large session into chunks", func(t *testing.T) {
		resp := redeemWith(t, testConfig(), "", large)

		require.Equal(t, uint32(302), resp.StatusCode)
		assert.Equal(t, []string{
			"_wormhole_session_0=" + large[:oauthapi.CookieChunkSize] + attrs,
			"_wormhole_session_1=tail" + attrs,
		}, setCookies(resp.Headers))
	})

	t.Run("surplus chunks and stale unsplit cookie are expired", func(t *testing.T) {
		resp := redeemWith(t, testConfig(),
			"_wormhole_session=old; _wormhole_session_0=a; _wormhole_session_1=b; _wormhole_session_2=c; _wormhole_session_csrf=k; other=1",
			large)

		assert.Equal(t, []string{
			"_wormhole_session_0=" + large[:oauthapi.CookieChunkSize] + attrs,
			"_wormhole_session_1=tail" + attrs,
			"_wormhole_session" + expired,
			"_wormhole_session_2" + expired,
		}, setCookies(resp.Headers), "unrelated cookies are untouched")
	})

	t.Run("small session replaces prior chunks", func(t *testing.T) {
		resp := redeemWith(t, testConfig(), "_wormhole_session_0=a; _wormhole_session_1=b", "small")

		assert.Equal(t, []string{
			"_wormhole_session=small" + attrs,
			"_wormhole_session_0" + expired,
			"_wormhole_session_1" + expired,
		}, setCookies(resp.Headers))
	})

	t.Run("redis store issues a single cookie", func(t *testing.T) {
		resp := redeemWith(t, redisConfig(), "", "ticket")

		assert.Equal(t, []string{"_wormhole_session=ticket" + attrs}, setCookies(resp.Headers))
	})

	t.Run("redis store rejects a session too large for one cookie", func(t *testing.T) {
		resp := redeemWith(t, redisConfig(), "", large)

		assert.Equal(t, uint32(500), resp.StatusCode)
		assert.Empty(t, setCookies(resp.Headers))
	})

	t.Run("session beyond the chunk limit is rejected", func(t *testing.T) {
		resp := redeemWith(t, testConfig(), "", strings.Repeat("a", oauthapi.CookieChunkSize*oauthapi.MaxCookieChunks+1))

		assert.Equal(t, uint32(500), resp.StatusCode)
		assert.Empty(t, setCookies(resp.Headers))
	})
}
