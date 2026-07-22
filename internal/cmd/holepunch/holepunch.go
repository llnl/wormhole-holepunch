package holepunch

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	"github.com/urfave/cli/v3"

	"github.com/llnl/wormhole-holepunch/internal/cacher"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/envoy"
	"github.com/llnl/wormhole-holepunch/internal/server"
	"github.com/llnl/wormhole-holepunch/internal/wormhole/registry"
)

func startAuthCmd(ctx context.Context, _ *cli.Command) error {
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ll := loadLogging()

	otelReq, shutdown := loadOTEL(ctx, ll)
	if otelReq {
		defer otelShutdown(ctx, ll, shutdown)
	}

	tokenAuth := loadAuthenticator(loadTokenStore(ctx, ll), ll)
	routeReg := loadRegistry(ctx, ll)

	ll.Info("starting up holepunch envoy-auth...")

	go manageRegistryRefresh(ctx, routeReg)

	return envoy.StartEnvoyAuth(ctx, ll, routeReg, tokenAuth, *tokenSvcArgs, *webArgs)
}

func startAdminCmd(ctx context.Context, _ *cli.Command) error {
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ll := loadLogging()

	otelReq, shutdown := loadOTEL(ctx, ll)
	if otelReq {
		defer otelShutdown(ctx, ll, shutdown)
	}

	tokenAuth := loadAuthenticator(loadTokenStore(ctx, ll), ll)
	routeReg := loadRegistry(ctx, ll)

	go manageRegistryRefresh(ctx, routeReg)

	return server.Configuration{
		Address: webArgs.ServerAddress,
	}.AdminAPI(ctx, ll, routeReg, tokenAuth)
}

func startCacherCmd(ctx context.Context, _ *cli.Command) error {
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ll := loadLogging()
	tokenAuth := loadAuthenticator(loadTokenStore(ctx, ll), ll)
	routeReg := loadRegistry(ctx, ll)

	ll.Info("starting up holepunch cacher...")

	return cacher.StartService(ctx, *cacheArgs, ll, routeReg, tokenAuth)
}

func startXDSCmd(ctx context.Context, _ *cli.Command) error {
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ll := loadLogging()

	otelReq, shutdown := loadOTEL(ctx, ll)
	if otelReq {
		defer otelShutdown(ctx, ll, shutdown)
	}

	routeReg := loadRegistry(ctx, ll)

	ll.Info("starting up holepunch envoy-xds...")

	go manageRegistryRefresh(ctx, routeReg)

	return envoy.RunServer(ctx, ll, routeReg, *tokenSvcArgs, *webArgs, *xdsArgs)
}

//

func manageRegistryRefresh(ctx context.Context, routeReg registry.Router) {
	err := routeReg.SubscribeToSources(ctx)
	if err != nil {
		log.Fatalf("failed to subscribe to route source: %s", err.Error())
	}
}

func otelShutdown(
	ctx context.Context,
	ll logs.Logger,
	shutdown func(context.Context) error,
) {
	err := shutdown(ctx)
	if err != nil {
		ll.Warn("failed otel shutdown: " + err.Error())
	}
}
