package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/paths"
	"github.com/llnl/wormhole-holepunch/internal/server"
)

const invalidJSONMsg = "invalid JSON payload"

func (d *data) adminHandlers() *http.ServeMux {
	mux := http.NewServeMux()

	// state
	mux.HandleFunc(paths.ControlsPath, d.ctlsReportHandler)

	// webhook
	mux.HandleFunc(paths.RoutesWebhookPath, d.routesWebhookHandler)
	mux.HandleFunc(paths.InvalidateWebhookPath, d.invalidateWebhookHandler)

	server.HandleCommon(mux)

	return mux
}

/*
	state related handlers
*/

func (d *data) ctlsReportHandler(w http.ResponseWriter, r *http.Request) {
	ll := logs.MustFromContext(r.Context())

	ctx, end := ll.StartSpan(r.Context(), "ctlsReportHandler")
	defer end()

	if server.MethodNotAllowed(ctx, http.MethodGet, ll, w, r) {
		return
	}

	server.JSONContentHeader(w)
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
	ll := logs.MustFromContext(r.Context())

	ctx, end := ll.StartSpan(r.Context(), "revokeWebhookHandler")
	defer end()

	if server.MethodNotAllowed(ctx, http.MethodPost, ll, w, r) {
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
	ll := logs.MustFromContext(r.Context())

	ctx, end := ll.StartSpan(r.Context(), "routesWebhookHandler")
	defer end()

	if server.MethodNotAllowed(ctx, http.MethodPost, ll, w, r) {
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "accepted",
	})

	d.routeReg.AsyncFetchSources()
}
