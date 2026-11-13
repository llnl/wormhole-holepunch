package server

import (
	"context"
	"net/http"

	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/paths"
)

// LedgerAPI serves the oauthmngr session hand-off callback (forwarded by Envoy's callback
// route), alongside the standard health and version endpoints. Access must be restricted to
// the Envoy pods (e.g., a NetworkPolicy); the callback trusts the client IP, host, and scheme
// headers Envoy sets on that route.
func (c Configuration) LedgerAPI(
	ctx context.Context,
	ll logs.Logger,
	callback http.Handler,
) error {
	ll.Info("starting oauthmngr ledger server on " + c.Address)

	d := &data{
		ll:  ll,
		cfg: c,
	}

	srv := c.initializeAdminServer(d, ledgerHandlers(callback))

	return runServer(ctx, ll, srv)
}

func ledgerHandlers(callback http.Handler) *http.ServeMux {
	mux := http.NewServeMux()

	mux.Handle(paths.CallbackPrefix, callback)

	mux.HandleFunc(paths.VersionPath, versionHandler)
	mux.HandleFunc(paths.HealthPath, healthzHandler)
	mux.HandleFunc("/", generic404Handler)

	return mux
}
