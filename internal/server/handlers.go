package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/version"
)

const (
	defaultPrefix = "/api/v1/"
	statePath     = defaultPrefix + "state/"
	webhookPath   = defaultPrefix + "webhook/"

	invalidJSONMsg = "invalid JSON payload"
)

func (d *data) adminHandlers() *http.ServeMux {
	mux := http.NewServeMux()

	// state
	mux.HandleFunc(statePath+"ctls", d.ctlsReportHandler)

	// webhook
	mux.HandleFunc(webhookPath+"routes", d.routesWebhookHandler)
	mux.HandleFunc(webhookPath+"invalidate", d.invalidateWebhookHandler)

	mux.HandleFunc(defaultPrefix+"version", versionHandler)
	mux.HandleFunc(defaultPrefix+"healthz", healthzHandler)
	mux.HandleFunc("/", generic404Handler)

	return mux
}

/*
	state related handlers
*/

func (d *data) ctlsReportHandler(w http.ResponseWriter, r *http.Request) {
	ll := mustGetLogger(r.Context())

	ctx, end := ll.StartSpan(r.Context(), "ctlsReportHandler")
	defer end()

	if methodNotAllowed(ctx, http.MethodGet, ll, w, r) {
		return
	}

	jsonContentHeader(w)
	_, _ = w.Write(d.routeReg.ReportControlsJSON())
}

/*
	webhook related handlers
*/

type revokePayload struct {
	TokenID   string           `json:"token_id" validate:"uuid"`
	Subtokens []revokeSubtoken `json:"subtokens" validate:"dive"`
}

type revokeSubtoken struct {
	TokenID    string `json:"token_id" validate:"uuid"`
	ExternalID string `json:"external_id" validate:"uuid"`
}

func (d *data) invalidateWebhookHandler(w http.ResponseWriter, r *http.Request) {
	ll := mustGetLogger(r.Context())

	ctx, end := ll.StartSpan(r.Context(), "revokeWebhookHandler")
	defer end()

	if methodNotAllowed(ctx, http.MethodPost, ll, w, r) {
		return
	}

	var payload revokePayload

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(&payload); err != nil {
		ll.WarnCtx(ctx, invalidJSONMsg+": "+err.Error())

		http.Error(w, invalidJSONMsg, http.StatusBadRequest)

		return
	}

	if sErr := d.vv.Struct(payload); sErr != nil {
		ll.WarnCtx(ctx, invalidJSONMsg+": "+sErr.Error())

		http.Error(w, invalidJSONMsg, http.StatusBadRequest)

		return
	}

	// Respond immediately (async processing)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusAccepted)

	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":   "accepted",
		"token_id": payload.TokenID,
	})

	// Run work asynchronously with a context that outlives the request.
	// nolint: gosec, contextcheck
	go func(p revokePayload) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		d.tokenAuth.InvalidateToken(ctx, p.TokenID)

		for _, v := range p.Subtokens {
			d.tokenAuth.RemoveSubtoken(ctx, p.TokenID, v.ExternalID, v.TokenID)
		}

		ll.InfoCtx(ctx, "revocation processed")
	}(payload)
}

func (d *data) routesWebhookHandler(w http.ResponseWriter, r *http.Request) {
	ll := mustGetLogger(r.Context())

	ctx, end := ll.StartSpan(r.Context(), "routesWebhookHandler")
	defer end()

	if methodNotAllowed(ctx, http.MethodPost, ll, w, r) {
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "accepted",
	})

	d.routeReg.AsyncFetchSources()
}

/*
	general handlers
*/

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	jsonContentHeader(w)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(fmt.Appendf(nil, `{"ok":true,"ts":"%s"}`+"\n", time.Now().UTC().Format(time.RFC3339Nano)))
}

func versionHandler(w http.ResponseWriter, r *http.Request) {
	ll := mustGetLogger(r.Context())

	ctx, end := ll.StartSpan(r.Context(), "versionHandler")
	defer end()

	if methodNotAllowed(ctx, http.MethodGet, ll, w, r) {
		return
	}

	jsonContentHeader(w)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(fmt.Appendf(nil, "{\"version\": \"%s\"}\n", version.GetVersion()))
}

func generic404Handler(w http.ResponseWriter, r *http.Request) {
	ll := mustGetLogger(r.Context())

	_, end := ll.StartSpan(r.Context(), "generic404Handler")
	defer end()

	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write(fmt.Append(nil, "404 Not Found"))
}

//

func jsonContentHeader(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
}

func methodNotAllowed(
	ctx context.Context,
	allowedMethod string,
	ll logs.Logger,
	w http.ResponseWriter,
	r *http.Request,
) bool {
	if r.Method == allowedMethod {
		return false
	}

	ll.WarnCtx(ctx, r.Method+" method not allowed")

	w.WriteHeader(http.StatusMethodNotAllowed)
	_, _ = w.Write([]byte(http.StatusText(http.StatusMethodNotAllowed)))

	return true
}
