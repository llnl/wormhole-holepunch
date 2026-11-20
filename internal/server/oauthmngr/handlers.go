package oauthmngr

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"

	"github.com/llnl/wormhole-holepunch/internal/ctls/cookies"
	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/paths"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr/ledger"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr/oauthapi"
	"github.com/llnl/wormhole-holepunch/internal/server"
)

func (d *data) oauthHandlers() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc(paths.CallbackPrefix, d.callbackHandler)

	server.HandleCommon(mux)

	return mux
}

/*
	callback related handlers
*/

// callbackRequest contains the trusted request metadata and browser cookies used by the callback.
type callbackRequest struct {
	nonce     string
	authority string
	scheme    string
	cookies   map[string]string
}

// callbackHandler proves browser continuity before capturing and redeeming the session.
// It trusts the host and scheme headers set by Envoy, so it must only be reachable through Envoy.
func (d *data) callbackHandler(w http.ResponseWriter, r *http.Request) {
	ll := logs.MustFromContext(r.Context())

	ctx, end := ll.StartSpan(r.Context(), "callbackHandler")
	defer end()

	r = r.WithContext(ctx)

	if !allowCallbackMethod(w, r.Method) {
		return
	}

	nonces := r.URL.Query()[oauthapi.NonceParam]
	if len(nonces) != 1 || !oauthapi.ValidNonce(nonces[0]) {
		ll.WarnCtx(ctx, "oauth callback rejected: missing or malformed nonce")
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	req := callbackRequest{
		nonce:     nonces[0],
		authority: r.Header.Get(keys.WormholeHostHeader),
		scheme:    r.Header.Get(keys.WormholeSchemeHeader),
		cookies:   oauthapi.ParseCookies(r.Header.Values(keys.CookieHeader)...),
	}

	if req.authority == "" {
		ll.ErrorCtx(ctx, "oauth callback rejected: request was not forwarded through Envoy's callback route")
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	if req.scheme != "https" || oauthapi.HTTPSOrigin(req.authority) == "" {
		ll.WarnCtx(ctx, "oauth callback requires an HTTPS origin")
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	if oauthapi.SameHTTPSAuthority(req.authority, d.cfg.AuthDomain) {
		d.authCallback(w, r, req)

		return
	}

	d.targetCallback(w, r, req)
}

func allowCallbackMethod(w http.ResponseWriter, method string) bool {
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodOptions:
		return true
	default:
		w.Header().Set(keys.AllowHeader, "GET, POST, OPTIONS")
		w.WriteHeader(http.StatusMethodNotAllowed)

		return false
	}
}

func (d *data) authCallback(w http.ResponseWriter, r *http.Request, req callbackRequest) {
	ll := logs.MustFromContext(r.Context())

	switch r.Method {
	case http.MethodGet:
		d.beginCapture(w, r, req)
	case http.MethodPost:
		if site := r.Header.Get(keys.SecFetchSiteHeader); site != "same-origin" {
			ll.WarnCtx(r.Context(), fmt.Sprintf("oauth complete rejected: %s %s, expected \"same-origin\"",
				http.CanonicalHeaderKey(keys.SecFetchSiteHeader), logValue(site)))
			w.WriteHeader(http.StatusForbidden)

			return
		}

		switch proof := r.Header.Get(keys.WormholeOAuthProofHeader); proof {
		case "complete":
			d.capture(w, r, req)
		case proofFailed:
			d.reportFailure(w, r)
		default:
			ll.WarnCtx(r.Context(), fmt.Sprintf("oauth complete rejected: %s header %s, expected \"complete\"",
				keys.WormholeOAuthProofHeader, logValue(proof)))
			w.WriteHeader(http.StatusForbidden)
		}
	default:
		w.Header().Set(keys.AllowHeader, "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// capture stores the auth-domain session against the nonce and returns the one-time code the
// auth page redeems on the target host.
func (d *data) capture(w http.ResponseWriter, r *http.Request, req callbackRequest) {
	ll := logs.MustFromContext(r.Context())

	ctx, end := ll.StartSpan(r.Context(), "capture")
	defer end()

	cookie, err := oauthapi.JoinCookie(req.cookies, d.cfg.ProxyCookieName, d.cfg.ProxySessionStore)

	switch {
	case errors.Is(err, oauthapi.ErrCookieNotFound):
		ll.WarnCtx(ctx, fmt.Sprintf("oauth2-proxy cookie %q not found at auth domain", d.cfg.ProxyCookieName))
		w.WriteHeader(http.StatusUnauthorized)

		return
	case err != nil:
		// Chunked cookies under Redis indicate a session-store configuration mismatch.
		ll.ErrorCtx(ctx, fmt.Sprintf("unusable oauth2-proxy cookie (proxy_session_store=%s): %s",
			d.cfg.ProxySessionStore, err))
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	proof := req.cookies[oauthapi.AuthProofCookiePrefix+req.nonce]
	if proof == "" {
		ll.WarnCtx(ctx, "oauth complete rejected: no auth proof cookie; it expires 60s after the proof "+
			"page loads, or was not sent by the browser")
		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	resp, err := d.flows.Capture(ctx, ledger.CaptureRequest{
		Nonce:         req.nonce,
		Authority:     req.authority,
		SessionCookie: cookie,
		AuthProof:     proof,
	})
	if err != nil {
		w.WriteHeader(errorStatus(ctx, "complete", err))
		return
	}

	expireCookie(ctx, w, req, oauthapi.AuthProofCookiePrefix+req.nonce, "/")
	w.Header().Set(keys.ContentTypeHeader, "text/plain; charset=utf-8")

	if _, err := w.Write([]byte(resp.RedeemCode)); err != nil {
		ll.WarnCtx(ctx, "unable to return OAuth redemption code")
	}
}

// redeem issues the host-only session cookie and returns the target URL for the auth page to
// navigate to. It is reached only through allowAuthOrigin, as a credentialed fetch from the
// auth page. It expires the binding cookie after success or a definitive rejection, but
// preserves it after transient failures.
func (d *data) redeem(w http.ResponseWriter, r *http.Request, req callbackRequest) {
	ll := logs.MustFromContext(r.Context())

	ctx, end := ll.StartSpan(r.Context(), "redeem")
	defer end()

	codes := r.Header.Values(keys.WormholeOAuthCodeHeader)
	if len(codes) != 1 || !oauthapi.ValidNonce(codes[0]) {
		ll.WarnCtx(ctx, fmt.Sprintf("oauth redeem rejected: expected one well-formed %s header, got %d",
			keys.WormholeOAuthCodeHeader, len(codes)))
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	bindingCookie := oauthapi.BindingCookieName(req.nonce)

	resp, err := d.flows.Redeem(ctx, ledger.RedeemRequest{
		Nonce:         req.nonce,
		Authority:     req.authority,
		BindingSecret: req.cookies[bindingCookie],
		Code:          codes[0],
	})
	if err != nil {
		status := errorStatus(ctx, "redeem", err)
		if status != http.StatusInternalServerError {
			expireCookie(ctx, w, req, bindingCookie, "/")
		}

		w.WriteHeader(status)

		return
	}

	expireCookie(ctx, w, req, bindingCookie, "/")

	sessionCookies, err := d.sessionCookies(resp.SessionHandle, req)
	if err != nil {
		ll.ErrorCtx(ctx, fmt.Sprintf("unable to issue session cookie: %s", err))
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	for _, c := range sessionCookies {
		http.SetCookie(w, c)
	}

	target := sameHostTarget(ctx, req, resp.TargetURL)

	ll.InfoCtx(
		ctx,
		"oauth session exchanged: issued host-only session",
		ll.StringArg("target", oauthapi.LogSafeURL(target)),
	)

	w.Header().Set(keys.ContentTypeHeader, "text/plain; charset=utf-8")

	if _, err := w.Write([]byte(target)); err != nil {
		ll.WarnCtx(ctx, "unable to return OAuth handoff destination")
	}
}

// errorStatus maps a ledger error for the named proof page step to its response status, logging
// it. The ledger logs the specific reason just before.
func errorStatus(ctx context.Context, step string, err error) int {
	ll := logs.MustFromContext(ctx)

	switch {
	case errors.Is(err, ledger.ErrInvalidRequest):
		ll.WarnCtx(ctx, fmt.Sprintf("oauth %s rejected: %s", step, err))
		return http.StatusBadRequest
	case errors.Is(err, ledger.ErrFlowUnavailable), errors.Is(err, ledger.ErrBindingMismatch):
		ll.WarnCtx(ctx, fmt.Sprintf("oauth %s rejected: %s", step, err))
		return http.StatusUnauthorized
	default:
		ll.ErrorCtx(ctx, fmt.Sprintf("oauth %s failed: %s", step, err))
		return http.StatusInternalServerError
	}
}

// sessionCookies builds the host-only session cookie holding the host session handle, and
// expires any chunks left by releases that stored the oauth2-proxy session in the cookie.
func (d *data) sessionCookies(handle string, req callbackRequest) ([]*http.Cookie, error) {
	session, err := cookies.NewResponse(d.cfg.SessionCookieName, handle, cookies.Options{
		MaxAge: d.cfg.SessionCookieMaxAge,
		Scheme: req.scheme,
	})
	if err != nil {
		return nil, err
	}

	out := []*http.Cookie{session}
	stale := make([]string, 0)

	for name := range req.cookies {
		if name != d.cfg.SessionCookieName && oauthapi.IsCookieOrChunk(d.cfg.SessionCookieName, name) {
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

func expireCookie(ctx context.Context, w http.ResponseWriter, req callbackRequest, name, path string) {
	c, err := cookies.NewResponse(name, "", cookies.Options{Path: path, MaxAge: -1, Scheme: req.scheme})
	if err != nil {
		logs.MustFromContext(ctx).WarnCtx(ctx, fmt.Sprintf("unable to expire cookie %q: %s", name, err))
		return
	}

	http.SetCookie(w, c)
}

// sameHostTarget accepts only HTTPS URLs on the current origin; otherwise it returns "/".
func sameHostTarget(ctx context.Context, req callbackRequest, target string) string {
	u, err := url.Parse(target)
	if err != nil ||
		u.Scheme != "https" || u.User != nil ||
		!oauthapi.SameHTTPSAuthority(u.Host, req.authority) {
		logs.MustFromContext(ctx).WarnCtx(ctx, "target URL is not on the callback host, redirecting to /")
		return "/"
	}

	return u.String()
}
