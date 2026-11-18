package oauthmngr

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/paths"
	"github.com/llnl/wormhole-holepunch/internal/ctls/streams"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr/ledger"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr/oauthapi"
	"github.com/llnl/wormhole-holepunch/internal/server"
)

// newNATSStore returns a ledger backed by an in-process JetStream bucket configured as in
// production: the bucket TTL covers sessions while flows carry per-key TTLs.
func newNATSStore(t *testing.T) *ledger.Store {
	t.Helper()

	srv, err := natsserver.NewServer(&natsserver.Options{
		Host: "127.0.0.1", Port: natsserver.RANDOM_PORT, JetStream: true,
		StoreDir: t.TempDir(), NoLog: true, NoSigs: true,
	})
	require.NoError(t, err)

	srv.Start()
	t.Cleanup(srv.Shutdown)
	require.True(t, srv.ReadyForConnections(5*time.Second))

	client, err := streams.Connect(args.Storage{StorageHost: srv.ClientURL(), NatsReplicas: 1}, ll)
	require.NoError(t, err)
	t.Cleanup(client.Close)

	kv, err := client.InitializeSessions(context.Background(), 12*time.Hour, 8<<20)
	require.NoError(t, err)

	store, err := ledger.New(kv, ll, testAuthDomain, 5*time.Minute, 12*time.Hour)
	require.NoError(t, err)

	return store
}

// browser replays the proof page's requests as a browser would send them through Envoy.
type browser struct {
	t       *testing.T
	handler http.Handler
	jar     map[string]map[string]string // host -> cookie name -> value
}

func (b *browser) do(method, host, path string, headers http.Header) *httptest.ResponseRecorder {
	b.t.Helper()

	req := httptest.NewRequest(method, path, nil)
	for k, v := range headers {
		req.Header[k] = v
	}

	// Envoy's callback route sets these from the matched virtual host.
	req.Header.Set(keys.WormholeHostHeader, host)
	req.Header.Set(keys.WormholeSchemeHeader, "https")

	pairs := make([]string, 0, len(b.jar[host]))
	for name, value := range b.jar[host] {
		pairs = append(pairs, name+"="+value)
	}

	if len(pairs) > 0 {
		req.Header.Set(keys.CookieHeader, strings.Join(pairs, "; "))
	}

	rec := httptest.NewRecorder()
	b.handler.ServeHTTP(rec, req)

	for _, c := range rec.Result().Cookies() { //nolint:bodyclose // recorder body
		if b.jar[host] == nil {
			b.jar[host] = map[string]string{}
		}

		if c.MaxAge < 0 {
			delete(b.jar[host], c.Name)
		} else {
			b.jar[host][c.Name] = c.Value
		}
	}

	return rec
}

// assertPreflight checks a preflight response carries everything a browser requires to send a
// credentialed POST with header from the auth origin.
func assertPreflight(t *testing.T, rec *httptest.ResponseRecorder, header string) {
	t.Helper()

	h := rec.Header()
	assert.Equal(t, "https://"+testAuthDomain, h.Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", h.Get("Access-Control-Allow-Credentials"))
	assert.Equal(t, http.MethodPost, h.Get("Access-Control-Allow-Methods"))
	assert.True(t, strings.EqualFold(header, h.Get("Access-Control-Allow-Headers")))
	assert.Contains(t, h.Values("Vary"), "Origin, Sec-Fetch-Site, Access-Control-Request-Method, Access-Control-Request-Headers")
}

// Test_proofPageFlow_NATS walks the full hand-off through the real handlers and ledger,
// issuing exactly the requests the proof page makes, in order.
func Test_proofPageFlow_NATS(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an in-process NATS server")
	}

	ctx := context.Background()
	store := newNATSStore(t)

	// Served exactly as API serves it, server middleware included.
	d := &data{ll: ll, flows: store, cfg: callbackConfig(oauthapi.SessionStoreRedis)}
	handler := server.Configuration{Address: ":0"}.NewHTTPServer(ll, d.oauthHandlers()).Handler
	b := &browser{t: t, handler: handler, jar: map[string]map[string]string{}}

	// Holepunch Auth mints the flow and sets the binding cookie on the application host.
	flow, err := store.Mint(ctx, ledger.MintRequest{
		TargetScheme: "https", TargetSubdomain: "foo.example.com", TargetURL: "https://foo.example.com/app",
	})
	require.NoError(t, err)

	b.jar["foo.example.com"] = map[string]string{oauthapi.BindingCookieName(flow.Nonce): flow.BindingSecret}
	b.jar[testAuthDomain] = map[string]string{"_oauth2_proxy": "proxy-session"}

	callback := paths.CallbackPrefix + "?nonce=" + flow.Nonce
	fromAuthPage := func(extra http.Header) http.Header {
		h := http.Header{"Origin": {"https://" + testAuthDomain}, "Sec-Fetch-Site": {"same-site"}}
		for k, v := range extra {
			h[k] = v
		}

		return h
	}

	// 1. oauth2-proxy redirects to the auth-host callback, which renders the proof page.
	page := b.do(http.MethodGet, testAuthDomain, callback, nil)
	require.Equal(t, http.StatusOK, page.Code)

	m := regexp.MustCompile(`"X-Wormhole-OAuth-Proof": "([A-Za-z0-9_-]+)"`).FindStringSubmatch(page.Body.String())
	require.Len(t, m, 2, "challenge rendered into the page")
	challenge := m[1]

	csp := page.Header().Get("Content-Security-Policy")
	assert.Contains(t, csp, "connect-src 'self' https://foo.example.com;", "the page may fetch the target")

	// 2. Authorize: preflight, then the credentialed POST to the target host.
	pre := b.do(http.MethodOptions, "foo.example.com", callback, fromAuthPage(http.Header{
		"Access-Control-Request-Method":  {"POST"},
		"Access-Control-Request-Headers": {"x-wormhole-oauth-proof"},
	}))
	require.Equal(t, http.StatusNoContent, pre.Code)
	assertPreflight(t, pre, proofHeader)

	authorize := b.do(http.MethodPost, "foo.example.com", callback, fromAuthPage(http.Header{
		http.CanonicalHeaderKey(proofHeader): {challenge},
	}))
	require.Equal(t, http.StatusNoContent, authorize.Code, "authorize")

	// 3. Complete: same-origin POST on the auth host captures the session.
	complete := b.do(http.MethodPost, testAuthDomain, callback, http.Header{
		http.CanonicalHeaderKey(proofHeader): {"complete"}, "Sec-Fetch-Site": {"same-origin"},
	})
	require.Equal(t, http.StatusOK, complete.Code, "complete")

	code := complete.Body.String()
	require.True(t, oauthapi.ValidNonce(code))

	// 4. Redeem: preflight, then the credentialed POST carrying the code.
	pre = b.do(http.MethodOptions, "foo.example.com", callback, fromAuthPage(http.Header{
		"Access-Control-Request-Method":  {"POST"},
		"Access-Control-Request-Headers": {"x-wormhole-oauth-code"},
	}))
	require.Equal(t, http.StatusNoContent, pre.Code)
	assertPreflight(t, pre, codeHeader)

	redeem := b.do(http.MethodPost, "foo.example.com", callback, fromAuthPage(http.Header{
		http.CanonicalHeaderKey(codeHeader): {code},
	}))
	require.Equal(t, http.StatusOK, redeem.Code, "redeem")
	assert.Equal(t, "https://foo.example.com/app", redeem.Body.String())
	assert.Equal(t, "https://"+testAuthDomain, redeem.Header().Get("Access-Control-Allow-Origin"))

	// 5. The browser now holds a host session that resolves only on foo.
	handle := b.jar["foo.example.com"]["_wormhole_session"]
	require.NotEmpty(t, handle)
	assert.NotContains(t, b.jar["foo.example.com"], oauthapi.BindingCookieName(flow.Nonce), "binding cookie expired")
	assert.NotContains(t, b.jar[testAuthDomain], oauthapi.AuthProofCookiePrefix+flow.Nonce, "proof cookie expired")

	session, err := store.ResolveHostSession(ctx, handle, "foo.example.com")
	require.NoError(t, err)
	assert.Equal(t, "proxy-session", session)
}
