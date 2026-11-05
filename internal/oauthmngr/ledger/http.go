package ledger

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/paths"
)

// maxLedgerRequestBytes bounds Ledger request bodies, comfortably above the largest single
// cookie a browser will send.
const maxLedgerRequestBytes = 64 << 10

// NewHandler exposes the Ledger over HTTP for the oauthmngr wasm plugin, following the
// contract documented on paths.CapturePath and paths.RedeemPath.
func NewHandler(l Ledger, ll logs.Logger) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST "+paths.CapturePath, func(w http.ResponseWriter, r *http.Request) {
		serveLedger(w, r, ll, l.Capture)
	})
	mux.HandleFunc("POST "+paths.RedeemPath, func(w http.ResponseWriter, r *http.Request) {
		serveLedger(w, r, ll, l.Redeem)
	})

	return mux
}

func serveLedger[Req, Resp any](
	w http.ResponseWriter,
	r *http.Request,
	ll logs.Logger,
	call func(context.Context, Req) (Resp, error),
) {
	var req Req

	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxLedgerRequestBytes))
	dec.DisallowUnknownFields()

	if err := dec.Decode(&req); err != nil {
		ll.Warnf("ledger request rejected: undecodable body: %s", err)
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	resp, err := call(r.Context(), req)

	switch {
	case err == nil:
	case errors.Is(err, ErrInvalidRequest):
		w.WriteHeader(http.StatusBadRequest)
		return
	case errors.Is(err, ErrFlowUnavailable), errors.Is(err, ErrBindingMismatch):
		w.WriteHeader(http.StatusForbidden)
		return
	default:
		ll.Errorf("ledger request failed: %s", err)
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		ll.Warnf("failed to write ledger response: %s", err)
	}
}
