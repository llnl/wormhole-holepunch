package admin

import (
	"context"

	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/rules"
	"github.com/llnl/wormhole-holepunch/internal/server"
	"github.com/llnl/wormhole-holepunch/internal/wormhole/registry"
	"github.com/llnl/wormhole-holepunch/internal/wormhole/token"
)

type data struct {
	ll        logs.Logger
	routeReg  registry.Router
	tokenAuth token.Authenticator
	vv        rules.Validator
}

// StartServer starts the web server for the Holepunch administrative endpoints (control
// state and webhooks) alongside the standard health and version endpoints.
func StartServer(
	ctx context.Context,
	cfg server.Configuration,
	ll logs.Logger,
	routeReg registry.Router,
	tokenAuth token.Authenticator,
) error {
	ll.Info("starting admin server on " + cfg.Address)

	d := &data{
		ll:        ll,
		routeReg:  routeReg,
		tokenAuth: tokenAuth,
		vv:        rules.NewValidator(),
	}

	return cfg.Serve(ctx, ll, d.adminHandlers())
}
