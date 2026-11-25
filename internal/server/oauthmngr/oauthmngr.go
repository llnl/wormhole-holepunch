package oauthmngr

import (
	"context"
	"fmt"

	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr/ledger"
	"github.com/llnl/wormhole-holepunch/internal/server"
)

// data holds the dependencies shared by the oauthmngr handlers. cfg must already be validated.
type data struct {
	ll    logs.Logger
	flows ledger.Ledger
	cfg   CallbackConfig
}

// StartServer starts the web server for the oauthmngr session hand-off callback (forwarded
// by Envoy's callback route), backed by flows, alongside the standard health and version
// endpoints. Access must be restricted to the Envoy pods (e.g., a NetworkPolicy); the
// callback trusts the host and scheme headers Envoy sets on that route. Flows are bound to
// browser proof, not client IP.
func StartServer(
	ctx context.Context,
	cfg server.Configuration,
	ll logs.Logger,
	flows ledger.Ledger,
	callbackCfg CallbackConfig,
) error {
	if err := callbackCfg.validate(); err != nil {
		return fmt.Errorf("invalid oauth callback configuration: %w", err)
	}

	ll.Info("starting oauthmngr ledger server on " + cfg.Address)

	d := &data{
		ll:    ll,
		flows: flows,
		cfg:   callbackCfg,
	}

	return cfg.Serve(ctx, ll, d.oauthHandlers())
}
