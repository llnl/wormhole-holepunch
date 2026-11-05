package oauthmngr

import (
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm"
	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm/types"

	"github.com/llnl/wormhole-holepunch/internal/ctls/paths"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr/oauthapi"
)

const (
	// maxLedgerResponseBytes bounds how much of a Ledger response is read.
	maxLedgerResponseBytes = 64 << 10
	// noGRPCStatus marks a local reply as a non-gRPC response.
	noGRPCStatus = -1
)

// httpContext handles a single request on the oauth-callback route.
type httpContext struct {
	types.DefaultHttpContext

	cfg *oauthapi.PluginConfig
}

// callbackRequest is the subset of the inbound request the plugin acts upon.
type callbackRequest struct {
	nonce     string
	authority string
	clientIP  string
	scheme    string
}

// OnHttpRequestHeaders always ends the request with a local reply, either immediately or
// once the Ledger callout completes.
func (h *httpContext) OnHttpRequestHeaders(int, bool) types.Action {
	req, status := h.readRequest()
	if status != 0 {
		return h.reply(status, nil)
	}

	if oauthapi.HostOnly(req.authority) == oauthapi.HostOnly(h.cfg.AuthDomain) {
		return h.capture(req)
	}

	return h.redeem(req)
}

// readRequest extracts and validates the callback request, returning a non-zero status
// when the request must be rejected.
func (h *httpContext) readRequest() (callbackRequest, uint32) {
	if method, _ := proxywasm.GetHttpRequestHeader(":method"); method != "GET" {
		return callbackRequest{}, statusMethodNotAllowed
	}

	rawPath, _ := proxywasm.GetHttpRequestHeader(":path")

	u, err := url.ParseRequestURI(rawPath)
	if err != nil || u.Path != paths.CallbackPrefix {
		return callbackRequest{}, statusNotFound
	}

	// Best effort: drop the query so the nonce isn't retained by access logs that record
	// the request path.
	_ = proxywasm.ReplaceHttpRequestHeader(":path", u.Path)

	nonces := u.Query()[oauthapi.NonceParam]
	if len(nonces) != 1 || !oauthapi.ValidNonce(nonces[0]) {
		proxywasm.LogWarn("oauthmngr: missing or malformed nonce")
		return callbackRequest{}, statusBadRequest
	}

	authority, _ := proxywasm.GetHttpRequestHeader(":authority")
	if authority == "" {
		return callbackRequest{}, statusBadRequest
	}

	// Must match the source used by ext_authz when minting the nonce: Envoy's
	// downstream remote address.
	addr, err := proxywasm.GetProperty([]string{"source", "address"})
	if err != nil || len(addr) == 0 {
		proxywasm.LogErrorf("oauthmngr: unable to determine client address: %v", err)
		return callbackRequest{}, statusInternalServerError
	}

	scheme, _ := proxywasm.GetHttpRequestHeader(":scheme")

	return callbackRequest{
		nonce:     nonces[0],
		authority: authority,
		clientIP:  oauthapi.HostOnly(string(addr)),
		scheme:    scheme,
	}, 0
}

// capture runs at the auth domain: the oauth2-proxy cookie (joined from chunks where the
// session store permits) is stored against the nonce and the user is redirected on to the
// target sub-domain callback.
func (h *httpContext) capture(req callbackRequest) types.Action {
	cookie, err := oauthapi.JoinCookie(requestCookies(), h.cfg.ProxyCookieName, h.cfg.ProxySessionStore)

	switch {
	case errors.Is(err, oauthapi.ErrCookieNotFound):
		proxywasm.LogWarnf("oauthmngr: oauth2-proxy cookie %q not found at auth domain", h.cfg.ProxyCookieName)
		return h.reply(statusUnauthorized, nil)
	case err != nil:
		// Chunks under the redis store, or more chunks than permitted, indicate oauth2-proxy
		// and Holepunch disagree on the session store.
		proxywasm.LogErrorf("oauthmngr: unusable oauth2-proxy cookie (proxy_session_store=%s): %v",
			h.cfg.ProxySessionStore, err)

		return h.reply(statusInternalServerError, nil)
	}

	return h.callLedger(paths.CapturePath, oauthapi.CaptureRequest{
		Nonce:         req.nonce,
		ClientIP:      req.clientIP,
		Authority:     req.authority,
		SessionCookie: cookie,
	}, func(body []byte) {
		var resp oauthapi.CaptureResponse
		if err := json.Unmarshal(body, &resp); err != nil || !validCallbackURL(resp.CallbackURL) {
			proxywasm.LogError("oauthmngr: invalid capture response from ledger")
			h.reply(statusInternalServerError, nil)

			return
		}

		h.reply(statusFound, [][2]string{{"location", resp.CallbackURL}})
	}, nil, nil)
}

// redeem runs at the target sub-domain: the captured session is exchanged for host-only
// session cookie(s) and the user is redirected to their intended destination.
func (h *httpContext) redeem(req callbackRequest) types.Action {
	// Read before the callout, the request headers are unavailable from its callback.
	existing := requestCookies()
	bindingCookie := oauthapi.BindingCookieName(req.nonce)

	expired, err := cookieHeader(bindingCookie, "", paths.CallbackPrefix, -1, req.scheme)
	if err != nil {
		proxywasm.LogErrorf("oauthmngr: unable to expire binding cookie: %v", err)
		return h.reply(statusInternalServerError, nil)
	}

	expireBindingCookie := [][2]string{{
		"set-cookie", expired,
	}}

	return h.callLedger(paths.RedeemPath, oauthapi.RedeemRequest{
		Nonce:         req.nonce,
		ClientIP:      req.clientIP,
		Authority:     req.authority,
		BindingSecret: existing[bindingCookie],
	}, func(body []byte) {
		var resp oauthapi.RedeemResponse
		if err := json.Unmarshal(body, &resp); err != nil || !validCookieValue(resp.SessionCookie) {
			proxywasm.LogError("oauthmngr: invalid redeem response from ledger")
			h.reply(statusInternalServerError, expireBindingCookie)

			return
		}

		setCookies, err := h.sessionCookies(resp.SessionCookie, req.scheme, existing)
		if err != nil {
			proxywasm.LogErrorf("oauthmngr: unable to issue session cookie (proxy_session_store=%s): %v",
				h.cfg.ProxySessionStore, err)
			h.reply(statusInternalServerError, expireBindingCookie)

			return
		}

		headers := append(
			[][2]string{{"location", sameHostTarget(resp.TargetURL, req.authority)}},
			setCookies...,
		)
		headers = append(headers, expireBindingCookie...)
		h.reply(statusFound, headers)
	}, expireBindingCookie, nil)
}

// callLedger dispatches a JSON request to the Ledger, pausing the stream until the callout
// completes. Only a 200 reaches onOK; every other outcome is answered with a local reply.
func (h *httpContext) callLedger(
	path string,
	payload any,
	onOK func(body []byte),
	onRejectedHeaders [][2]string,
	onFailureHeaders [][2]string,
) types.Action {
	body, err := json.Marshal(payload)
	if err != nil {
		return h.reply(statusInternalServerError, onFailureHeaders)
	}

	headers := [][2]string{
		{":method", "POST"},
		{":path", path},
		{":authority", h.cfg.LedgerCluster},
		{"content-type", "application/json"},
	}

	_, err = proxywasm.DispatchHttpCall(
		h.cfg.LedgerCluster,
		headers,
		body,
		nil,
		uint32(h.cfg.LedgerTimeoutMs), //nolint:gosec // validated non-negative in parseConfig
		func(numHeaders, bodySize, _ int) {
			status, respBody := ledgerResponse(numHeaders, bodySize)

			switch status {
			case statusOK:
				onOK(respBody)
			case statusBadRequest:
				h.reply(statusBadRequest, onRejectedHeaders)
			case statusForbidden:
				h.reply(statusUnauthorized, onRejectedHeaders)
			default:
				proxywasm.LogErrorf("oauthmngr: ledger %s failed (status=%d)", path, status)
				h.reply(statusInternalServerError, onFailureHeaders)
			}
		},
	)
	if err != nil {
		proxywasm.LogErrorf("oauthmngr: unable to dispatch ledger %s: %v", path, err)
		return h.reply(statusInternalServerError, onFailureHeaders)
	}

	return types.ActionPause
}

// reply sends a local response that must never be cached and never leaks the callback URL
// (and its nonce) through the Referer header.
func (h *httpContext) reply(status uint32, headers [][2]string) types.Action {
	headers = append(headers,
		[2]string{"cache-control", "no-store"},
		[2]string{"referrer-policy", "no-referrer"},
	)

	if err := proxywasm.SendHttpResponse(status, headers, nil, noGRPCStatus); err != nil {
		proxywasm.LogErrorf("oauthmngr: unable to send local reply: %v", err)
	}

	return types.ActionPause
}

// sessionCookies builds the Set-Cookie headers for the host-only sub-domain session, split
// into chunks where the session store permits. Any of the session's cookies already held by
// the browser that are not being replaced (e.g., surplus chunks from a larger, prior session)
// are expired, so they can never be joined onto the new session.
func (h *httpContext) sessionCookies(value, scheme string, existing map[string]string) ([][2]string, error) {
	pairs, err := oauthapi.SplitCookie(h.cfg.SessionCookieName, value, h.cfg.ProxySessionStore)
	if err != nil {
		return nil, err
	}

	issued := make(map[string]struct{}, len(pairs))
	headers := make([][2]string, 0, len(pairs))

	for _, p := range pairs {
		cookie, err := cookieHeader(p[0], p[1], "/", h.cfg.SessionCookieMaxAge, scheme)
		if err != nil {
			return nil, err
		}

		issued[p[0]] = struct{}{}

		headers = append(headers, [2]string{"set-cookie", cookie})
	}

	stale := make([]string, 0)

	for name := range existing {
		if _, ok := issued[name]; !ok && oauthapi.IsCookieOrChunk(h.cfg.SessionCookieName, name) {
			stale = append(stale, name)
		}
	}

	slices.Sort(stale)

	for _, name := range stale {
		cookie, err := cookieHeader(name, "", "/", -1, scheme)
		if err != nil {
			return nil, err
		}

		headers = append(headers, [2]string{"set-cookie", cookie})
	}

	return headers, nil
}

//

// ledgerResponse returns the status and body of the completed callout, a zero status
// indicating the callout failed (e.g., timeout or reset).
func ledgerResponse(numHeaders, bodySize int) (int, []byte) {
	if numHeaders == 0 {
		return 0, nil
	}

	headers, err := proxywasm.GetHttpCallResponseHeaders()
	if err != nil {
		return 0, nil
	}

	status := 0

	for _, hdr := range headers {
		if hdr[0] == ":status" {
			status, _ = strconv.Atoi(hdr[1])
		}
	}

	if bodySize <= 0 {
		return status, nil
	}

	body, err := proxywasm.GetHttpCallResponseBody(0, min(bodySize, maxLedgerResponseBytes))
	if err != nil {
		return 0, nil
	}

	return status, body
}

// requestCookies parses every Cookie header on the request (HTTP/2 may send several).
func requestCookies() map[string]string {
	headers, err := proxywasm.GetHttpRequestHeaders()
	if err != nil {
		return map[string]string{}
	}

	values := make([]string, 0)

	for _, hdr := range headers {
		if strings.EqualFold(hdr[0], "cookie") {
			values = append(values, hdr[1])
		}
	}

	return oauthapi.ParseCookies(values...)
}

// validCallbackURL ensures the Ledger directed us to a sub-domain callback.
func validCallbackURL(raw string) bool {
	u, err := url.Parse(raw)

	return err == nil &&
		(u.Scheme == "https" || u.Scheme == "http") &&
		u.Host != "" &&
		u.Path == paths.CallbackPrefix
}

// sameHostTarget returns the target when it is an absolute http(s) URL on the current
// host, otherwise the host's root. The cookie just issued is host-only, so redirecting
// anywhere else would only restart the flow.
func sameHostTarget(target, authority string) string {
	u, err := url.Parse(target)
	if err != nil ||
		(u.Scheme != "https" && u.Scheme != "http") ||
		oauthapi.HostOnly(u.Host) != oauthapi.HostOnly(authority) {
		proxywasm.LogWarn("oauthmngr: target URL is not on the callback host, redirecting to /")
		return "/"
	}

	return u.String()
}

// validCookieName reports whether name is an RFC 6265 token.
func validCookieName(name string) bool {
	if name == "" {
		return false
	}

	for _, c := range []byte(name) {
		if c <= ' ' || c >= 0x7f || strings.IndexByte(`()<>@,;:\"/[]?={}`, c) >= 0 {
			return false
		}
	}

	return true
}

// validCookieValue reports whether value consists solely of RFC 6265 cookie-octets.
func validCookieValue(value string) bool {
	if value == "" {
		return false
	}

	for _, c := range []byte(value) {
		if c <= ' ' || c >= 0x7f || c == '"' || c == ',' || c == ';' || c == '\\' {
			return false
		}
	}

	return true
}
