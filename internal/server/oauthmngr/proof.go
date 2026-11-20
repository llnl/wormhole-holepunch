package oauthmngr

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/llnl/wormhole-holepunch/internal/ctls/cookies"
	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/paths"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr/ledger"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr/oauthapi"
)

// proofFailed reports a failed step to the auth host.
const proofFailed = "failed"

// proofPage finishes the flow from the auth origin. Every request to the target host is a
// credentialed fetch made by this page, so the redemption code never appears in a URL the
// target host navigates to, where script it serves (e.g., a service worker) could read it.
// The page only navigates to the target once the session cookie is set.
//
// On failure it names the step and HTTP status (or that the browser blocked the request, which
// is all a fetch reveals of a CORS, CSP, or network failure), logs it to the console, and
// reports it to the auth host so it also appears in the oauthmngr logs.
var proofPage = template.Must(template.New("oauth-proof").Parse(`<!doctype html>
<html lang="en"><meta charset="utf-8"><title>Finishing sign-in</title>
<p id="status">Finishing sign-in...</p>
<noscript>JavaScript is required to finish sign-in.</noscript>
<script nonce="{{.CSPNonce}}">
let step = "";
const send = async (name, url, headers, credentials) => {
    step = name;
    const res = await fetch(url, {method: "POST", credentials, redirect: "error", headers});
    if (!res.ok) throw Object.assign(new Error("HTTP " + res.status), {status: res.status});
    return res;
};
(async () => {
    await send("authorize", {{.Target}}, { {{- .ProofHeader -}}: {{.Challenge}}}, "include");
    const complete = await send("complete", window.location.href,
        { {{- .ProofHeader -}}: "complete"}, "same-origin");
    const code = await complete.text();
    const redeem = await send("redeem", {{.Target}}, { {{- .CodeHeader -}}: code}, "include");
    step = "navigate";
    window.location.replace(await redeem.text());
})().catch((err) => {
    const status = (err && err.status) || 0;
    const error = String((err && err.message) || err).slice(0, 200);
    console.error("Sign-in failed at step " + step + ": " +
        (status ? error : "request blocked by the browser (CORS, CSP, or network): " + error), err);
    document.getElementById("status").textContent = "Could not finish sign-in (" + step + ": " +
        (status ? "HTTP " + status : "request blocked") + "). Return to the application and try again.";
    fetch(window.location.href, {
        method: "POST", credentials: "same-origin", keepalive: true,
        headers: { {{- .ProofHeader -}}: "failed", {{.ContentTypeHeader}}: "application/json"},
        body: JSON.stringify({step, status, error})
    }).catch(() => {});
});
</script></html>`))

func (d *data) beginCapture(w http.ResponseWriter, r *http.Request, req callbackRequest) {
	start, err := d.flows.BeginCapture(r.Context(), req.nonce)
	if err != nil {
		w.WriteHeader(errorStatus(req.ll, "begin capture", err))

		return
	}

	target := oauthapi.HTTPSOrigin(start.TargetAuthority)
	if target == "" || target == oauthapi.HTTPSOrigin(d.cfg.AuthDomain) {
		req.ll.Warnf("oauth callback rejected: flow target %q is not a distinct HTTPS application origin",
			start.TargetAuthority)
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	// The challenge is random and HTML-only; the cookie carries its preimage.
	page := struct{ CSPNonce, Target, Challenge, ProofHeader, CodeHeader, ContentTypeHeader string }{
		CSPNonce:          rand.Text(),
		Target:            target + paths.CallbackPrefix + "?nonce=" + url.QueryEscape(req.nonce),
		Challenge:         start.Challenge,
		ProofHeader:       http.CanonicalHeaderKey(keys.WormholeOAuthProofHeader),
		CodeHeader:        http.CanonicalHeaderKey(keys.WormholeOAuthCodeHeader),
		ContentTypeHeader: http.CanonicalHeaderKey(keys.ContentTypeHeader),
	}

	var body bytes.Buffer
	if err := proofPage.Execute(&body, page); err != nil {
		req.ll.Error("unable to render OAuth browser proof page")
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	cookie, err := cookies.NewResponse(oauthapi.AuthProofCookiePrefix+req.nonce, start.AuthProof,
		cookies.Options{Path: "/", MaxAge: 60, Scheme: "https"})
	if err != nil {
		req.ll.Error("unable to issue OAuth browser proof cookie")
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	http.SetCookie(w, cookie)
	w.Header().Set(keys.ContentTypeHeader, "text/html; charset=utf-8")
	w.Header().Set(keys.ContentSecurityPolicyHeader, "default-src 'none'; script-src 'nonce-"+page.CSPNonce+
		"'; connect-src 'self' "+target+"; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")

	if _, err := body.WriteTo(w); err != nil {
		req.ll.Warn("unable to return OAuth browser proof page")
	}
}

// targetCallback serves the target host's callback, which only the auth page's credentialed
// fetches use: a POST carrying the code header redeems the flow, any other POST authorizes it.
func (d *data) targetCallback(w http.ResponseWriter, r *http.Request, req callbackRequest) {
	if r.Method != http.MethodPost && r.Method != http.MethodOptions {
		// Redemption by navigation would expose the code to script served by the target host.
		w.Header().Set(keys.AllowHeader, "POST, OPTIONS")
		w.WriteHeader(http.StatusMethodNotAllowed)

		return
	}

	if !d.allowAuthOrigin(w, r, req) {
		return
	}

	if r.Header.Get(keys.WormholeOAuthCodeHeader) != "" {
		d.redeem(w, r, req)

		return
	}

	d.authorizeCapture(w, r, req)
}

// allowAuthOrigin admits only CORS requests from the auth page, answering preflights itself.
// It reports whether the caller should go on to serve the POST.
func (d *data) allowAuthOrigin(w http.ResponseWriter, r *http.Request, req callbackRequest) bool {
	h := w.Header()
	h.Add(keys.VaryHeader, http.CanonicalHeaderKey(keys.OriginHeader)+
		", "+http.CanonicalHeaderKey(keys.SecFetchSiteHeader)+
		", "+http.CanonicalHeaderKey(keys.AccessControlRequestMethodHeader)+
		", "+http.CanonicalHeaderKey(keys.AccessControlRequestHeadersHeader))

	origin := oauthapi.HTTPSOrigin(d.cfg.AuthDomain)
	if got := r.Header.Get(keys.OriginHeader); origin == "" || got != origin {
		req.ll.Warnf("oauth callback rejected: %s from origin %s, expected %q", r.Method, logValue(got), origin)
		w.WriteHeader(http.StatusForbidden)

		return false
	}

	// From here the requester is the auth page, so let it read the status of any rejection;
	// without these headers the browser only reports an opaque network error.
	h.Set(keys.AccessControlAllowOriginHeader, origin)
	h.Set(keys.AccessControlAllowCredentialsHeader, "true")

	if site := r.Header.Get(keys.SecFetchSiteHeader); site != "same-site" {
		req.ll.Warnf("oauth callback rejected: %s with %s %s, expected \"same-site\" "+
			"(the auth and application hosts must share a registrable domain)",
			r.Method, http.CanonicalHeaderKey(keys.SecFetchSiteHeader), logValue(site))
		w.WriteHeader(http.StatusForbidden)

		return false
	}

	// A preflight may ask for exactly one of the two headers the auth page sends.
	var allowHeader string

	requested := r.Header.Get(keys.AccessControlRequestHeadersHeader)

	switch {
	case strings.EqualFold(requested, keys.WormholeOAuthProofHeader):
		allowHeader = http.CanonicalHeaderKey(keys.WormholeOAuthProofHeader)
	case strings.EqualFold(requested, keys.WormholeOAuthCodeHeader):
		allowHeader = http.CanonicalHeaderKey(keys.WormholeOAuthCodeHeader)
	}

	if method := r.Header.Get(keys.AccessControlRequestMethodHeader); r.Method == http.MethodOptions &&
		(method != http.MethodPost || allowHeader == "") {
		req.ll.Warnf("oauth callback rejected: preflight for method %s with headers %s, expected POST with %q or %q",
			logValue(method), logValue(requested), keys.WormholeOAuthProofHeader, keys.WormholeOAuthCodeHeader)
		w.WriteHeader(http.StatusBadRequest)

		return false
	}

	if r.Method == http.MethodOptions {
		h.Set(keys.AccessControlAllowMethodsHeader, http.MethodPost)
		h.Set(keys.AccessControlAllowHeadersHeader, allowHeader)
		w.WriteHeader(http.StatusNoContent)

		return false
	}

	return true
}

func (d *data) authorizeCapture(w http.ResponseWriter, r *http.Request, req callbackRequest) {
	binding := req.cookies[oauthapi.BindingCookieName(req.nonce)]
	if binding == "" {
		req.ll.Warnf("oauth authorize rejected: no binding cookie on %s; it expired with the nonce, "+
			"was not sent by the browser, or sign-in finished in a different browser", req.authority)
		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	err := d.flows.AuthorizeCapture(r.Context(), ledger.AuthorizeRequest{
		Nonce:         req.nonce,
		Authority:     req.authority,
		BindingSecret: binding,
		Challenge:     r.Header.Get(keys.WormholeOAuthProofHeader),
	})
	if err != nil {
		w.WriteHeader(errorStatus(req.ll, "authorize", err))

		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// maxFailureReport bounds the failure report body read from the proof page.
const maxFailureReport = 1024

// reportFailure logs a failure the proof page observed. Failures the browser blocks (CORS,
// CSP, network) never reach oauthmngr otherwise. The report is unauthenticated, so it is only
// logged, with every field bounded and quoted.
func (d *data) reportFailure(w http.ResponseWriter, r *http.Request, req callbackRequest) {
	var report struct {
		Step   string `json:"step"`
		Status int    `json:"status"`
		Error  string `json:"error"`
	}

	if err := json.NewDecoder(io.LimitReader(r.Body, maxFailureReport)).Decode(&report); err != nil {
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	detail := "HTTP " + strconv.Itoa(report.Status)
	if report.Status == 0 {
		detail = "request blocked by the browser (CORS, CSP, or network); check the preceding " +
			"oauth callback logs for a rejected preflight"
	}

	req.ll.Warnf("oauth sign-in failed in the browser at step %s: %s (%s)",
		logValue(report.Step), detail, logValue(report.Error))
	w.WriteHeader(http.StatusNoContent)
}

// logValue quotes and bounds an untrusted value for logging.
func logValue(s string) string {
	const maxLen = 120

	if len(s) > maxLen {
		s = s[:maxLen] + "..."
	}

	return strconv.Quote(s)
}
