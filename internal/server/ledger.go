package server

import (
	"context"
	"net/http"

	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/paths"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr/ledger"
)

// LedgerAPI serves the oauthmngr session Ledger to the oauthmngr wasm plugin (via Envoy's
// ledger cluster), alongside the standard health and version endpoints. Access must be
// restricted to the Envoy pods (e.g., a NetworkPolicy); the endpoints carry no other
// authentication. Request bodies (nonces, session cookies) are never logged.
func (c Configuration) LedgerAPI(
	ctx context.Context,
	ll logs.Logger,
	flowLedger ledger.Ledger,
) error {
	ll.Info("starting oauthmngr ledger server on " + c.Address)

	d := &data{
		ll:  ll,
		cfg: c,
	}

	srv := c.initializeAdminServer(d, ledgerHandlers(ll, flowLedger))

	return runServer(ctx, ll, srv)
}

func ledgerHandlers(ll logs.Logger, flowLedger ledger.Ledger) *http.ServeMux {
	ledgerHandler := ledger.NewHandler(flowLedger, ll)

	mux := http.NewServeMux()

	mux.Handle(paths.CapturePath, ledgerHandler)
	mux.Handle(paths.RedeemPath, ledgerHandler)

	mux.HandleFunc(paths.VersionPath, versionHandler)
	mux.HandleFunc(paths.HealthPath, healthzHandler)
	mux.HandleFunc("/", generic404Handler)

	return mux
}
