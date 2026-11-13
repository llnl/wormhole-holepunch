package ledger

import (
	"errors"
	"net/http"
	"net/url"
	"slices"

	"github.com/llnl/wormhole-holepunch/internal/ctls/cookies"
	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/paths"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr/oauthapi"
)

// CallbackConfig configures the session hand-off callback served at paths.CallbackPrefix.
type CallbackConfig struct {
	// AuthDomain is the shared auth host; callbacks made against it capture the session,
	// callbacks on any other host redeem it.
	AuthDomain string
	// ProxyCookieName is the oauth2-proxy session cookie captured at the auth domain.
	ProxyCookieName string
	// ProxySessionStore must match oauth2-proxy's session_store_type, it determines whether
	// chunked cookies are read at the auth domain and issued on the sub-domain.
	ProxySessionStore oauthapi.SessionStore
	// SessionCookieName and SessionCookieMaxAge describe the host-only session cookie
	// issued on the target sub-domain.
	SessionCookieName   string
	SessionCookieMaxAge int
}

// callbackHandler completes the oauth2-proxy-middleware hand-off (see docs/oauth-manager.md):
//
//   - At the auth domain it captures the oauth2-proxy session cookie against the nonce, then
//     redirects to the target sub-domain callback.
//   - At the target sub-domain it redeems the nonce, then redirects to the user's intended
//     destination with a host-only sub-domain session cookie.
type callbackHandler struct {
	cfg    CallbackConfig
	ledger Ledger
	ll     logs.Logger
}

// callbackRequest is the subset of the inbound request the callback acts upon.
type callbackRequest struct {
	nonce     string
	authority string
	clientIP  string
	scheme    string
	cookies   map[string]string
}

// NewCallbackHandler serves the callback, which Envoy forwards with ext_authz disabled. The
// client IP, host, and scheme are taken from headers Envoy sets on the callback route,
// so the handler must only be reachable through Envoy.
func NewCallbackHandler(l Ledger, cfg CallbackConfig, ll logs.Logger) (http.Handler, error) {
	switch {
	case cfg.AuthDomain == "":
		return nil, errors.New("user auth URL is required by the callback")
	case !validCookieName(cfg.ProxyCookieName):
		return nil, errors.New("proxy cookie name must be a valid cookie name")
	case !validCookieName(cfg.SessionCookieName):
		return nil, errors.New("session cookie name must be a valid cookie name")
	case cfg.SessionCookieMaxAge <= 0:
		return nil, errors.New("session cookie max age must be positive")
	case !cfg.ProxySessionStore.Valid():
		return nil, errors.New("proxy session store is not supported")
	}

	h := &callbackHandler{cfg: cfg, ledger: l, ll: ll}

	mux := http.NewServeMux()
	mux.Handle("GET "+paths.CallbackPrefix, h)

	return mux, nil
}

func (h *callbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Never cache, and never leak the callback URL (and its nonce) through the Referer header.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")

	nonces := r.URL.Query()[oauthapi.NonceParam]
	if len(nonces) != 1 || !oauthapi.ValidNonce(nonces[0]) {
		h.ll.Warn("oauth callback rejected: missing or malformed nonce")
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	req := callbackRequest{
		nonce:     nonces[0],
		authority: r.Header.Get(keys.WormholeHostHeader),
		clientIP:  r.Header.Get(keys.ClientIPHeader),
		scheme:    r.Header.Get(keys.WormholeSchemeHeader),
		cookies:   oauthapi.ParseCookies(r.Header.Values(keys.CookieHeader)...),
	}

	if req.authority == "" || req.clientIP == "" {
		h.ll.Error("oauth callback rejected: request was not forwarded through Envoy's callback route")
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	if oauthapi.HostOnly(req.authority) == oauthapi.HostOnly(h.cfg.AuthDomain) {
		h.capture(w, r, req)
		return
	}

	h.redeem(w, r, req)
}

// capture runs at the auth domain: the oauth2-proxy cookie (joined from chunks where the
// session store permits) is stored against the nonce and the user is redirected on to the
// target sub-domain callback.
func (h *callbackHandler) capture(w http.ResponseWriter, r *http.Request, req callbackRequest) {
	cookie, err := oauthapi.JoinCookie(req.cookies, h.cfg.ProxyCookieName, h.cfg.ProxySessionStore)

	switch {
	case errors.Is(err, oauthapi.ErrCookieNotFound):
		h.ll.Warnf("oauth2-proxy cookie %q not found at auth domain", h.cfg.ProxyCookieName)
		w.WriteHeader(http.StatusUnauthorized)

		return
	case err != nil:
		// Chunks under the redis store, or more chunks than permitted, indicate oauth2-proxy
		// and Holepunch disagree on the session store.
		h.ll.Errorf("unusable oauth2-proxy cookie (proxy_session_store=%s): %s", h.cfg.ProxySessionStore, err)
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	resp, err := h.ledger.Capture(r.Context(), CaptureRequest{
		Nonce:         req.nonce,
		ClientIP:      req.clientIP,
		Authority:     req.authority,
		SessionCookie: cookie,
	})
	if err != nil {
		w.WriteHeader(h.errorStatus(err))
		return
	}

	http.Redirect(w, r, resp.CallbackURL, http.StatusFound)
}

// redeem runs at the target sub-domain: the captured session is exchanged for host-only
// session cookie(s) and the user is redirected to their intended destination. The binding
// cookie is expired once the flow is consumed or definitively rejected; a transient failure
// preserves it so the callback may be retried until it expires.
func (h *callbackHandler) redeem(w http.ResponseWriter, r *http.Request, req callbackRequest) {
	bindingCookie := oauthapi.BindingCookieName(req.nonce)

	resp, err := h.ledger.Redeem(r.Context(), RedeemRequest{
		Nonce:         req.nonce,
		ClientIP:      req.clientIP,
		Authority:     req.authority,
		BindingSecret: req.cookies[bindingCookie],
	})
	if err != nil {
		status := h.errorStatus(err)
		if status != http.StatusInternalServerError {
			h.expireCookie(w, bindingCookie, paths.CallbackPrefix, req.scheme)
		}

		w.WriteHeader(status)

		return
	}

	h.expireCookie(w, bindingCookie, paths.CallbackPrefix, req.scheme)

	sessionCookies, err := h.sessionCookies(resp.SessionCookie, req)
	if err != nil {
		h.ll.Errorf("unable to issue session cookie (proxy_session_store=%s): %s", h.cfg.ProxySessionStore, err)
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	for _, c := range sessionCookies {
		http.SetCookie(w, c)
	}

	http.Redirect(w, r, h.sameHostTarget(resp.TargetURL, req.authority), http.StatusFound)
}

// errorStatus maps a Ledger error to the callback's response status.
func (h *callbackHandler) errorStatus(err error) int {
	switch {
	case errors.Is(err, ErrInvalidRequest):
		return http.StatusBadRequest
	case errors.Is(err, ErrFlowUnavailable), errors.Is(err, ErrBindingMismatch):
		return http.StatusUnauthorized
	default:
		h.ll.Errorf("oauth callback failed: %s", err)
		return http.StatusInternalServerError
	}
}

// sessionCookies builds the host-only sub-domain session cookies, split into chunks where
// the session store permits. Any of the session's cookies already held by the browser that
// are not being replaced (e.g., surplus chunks from a larger, prior session) are expired, so
// they can never be joined onto the new session.
func (h *callbackHandler) sessionCookies(value string, req callbackRequest) ([]*http.Cookie, error) {
	pairs, err := oauthapi.SplitCookie(h.cfg.SessionCookieName, value, h.cfg.ProxySessionStore)
	if err != nil {
		return nil, err
	}

	issued := make(map[string]struct{}, len(pairs))
	out := make([]*http.Cookie, 0, len(pairs))

	for _, p := range pairs {
		c, err := cookies.NewResponse(p[0], p[1], cookies.Options{
			MaxAge: h.cfg.SessionCookieMaxAge,
			Scheme: req.scheme,
		})
		if err != nil {
			return nil, err
		}

		issued[p[0]] = struct{}{}

		out = append(out, c)
	}

	stale := make([]string, 0)

	for name := range req.cookies {
		if _, ok := issued[name]; !ok && oauthapi.IsCookieOrChunk(h.cfg.SessionCookieName, name) {
			stale = append(stale, name)
		}
	}

	slices.Sort(stale)

	for _, name := range stale {
		c, err := cookies.NewResponse(name, "", cookies.Options{MaxAge: -1, Scheme: req.scheme})
		if err != nil {
			return nil, err
		}

		out = append(out, c)
	}

	return out, nil
}

func (h *callbackHandler) expireCookie(w http.ResponseWriter, name, path, scheme string) {
	c, err := cookies.NewResponse(name, "", cookies.Options{Path: path, MaxAge: -1, Scheme: scheme})
	if err != nil {
		h.ll.Warnf("unable to expire cookie %q: %s", name, err)
		return
	}

	http.SetCookie(w, c)
}

// sameHostTarget returns the target when it is an absolute http(s) URL on the current
// host, otherwise the host's root. The cookie just issued is host-only, so redirecting
// anywhere else would only restart the flow.
func (h *callbackHandler) sameHostTarget(target, authority string) string {
	u, err := url.Parse(target)
	if err != nil ||
		(u.Scheme != "https" && u.Scheme != "http") ||
		oauthapi.HostOnly(u.Host) != oauthapi.HostOnly(authority) {
		h.ll.Warn("target URL is not on the callback host, redirecting to /")
		return "/"
	}

	return u.String()
}

func validCookieName(name string) bool {
	_, err := cookies.NewRequest(name, "")

	return err == nil
}
