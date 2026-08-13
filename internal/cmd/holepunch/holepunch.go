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
	ctx, stop, ll := defaultInit(ctx)
	defer stop()

	otelReq, shutdown := loadOTEL(ctx, ll)
	if otelReq {
		defer otelShutdown(ctx, ll, shutdown)
	}

	tokenStore := loadTokenStore(ctx, ll)
	sessionStore := loadSessionStore(ctx, ll)
	oauthValid := loadOauthMngr(sessionStore, ll)

	tokenAuth := loadAuthenticator(tokenStore, ll)
	routeReg := loadRegistry(ctx, ll, oauthValid)

	ll.Info("starting up holepunch envoy-auth...")

	go manageRegistryRefresh(ctx, routeReg)

	return envoy.StartEnvoyAuth(ctx, ll, oauthValid, routeReg, tokenAuth, *tokenSvcArgs, *webArgs)
}

func startAdminCmd(ctx context.Context, _ *cli.Command) error {
	ctx, stop, ll := defaultInit(ctx)
	defer stop()

	otelReq, shutdown := loadOTEL(ctx, ll)
	if otelReq {
		defer otelShutdown(ctx, ll, shutdown)
	}

	tokenStore := loadTokenStore(ctx, ll)
	sessionStore := loadSessionStore(ctx, ll)
	oauthValid := loadOauthMngr(sessionStore, ll)

	tokenAuth := loadAuthenticator(tokenStore, ll)
	routeReg := loadRegistry(ctx, ll, oauthValid)

	go manageRegistryRefresh(ctx, routeReg)

	return server.Configuration{
		Address: webArgs.ServerAddress,
	}.AdminAPI(ctx, ll, routeReg, tokenAuth)
}

func startCacherCmd(ctx context.Context, _ *cli.Command) error {
	ctx, stop, ll := defaultInit(ctx)
	defer stop()

	tokenStore := loadTokenStore(ctx, ll)
	sessionStore := loadSessionStore(ctx, ll)
	oauthValid := loadOauthMngr(sessionStore, ll)

	tokenAuth := loadAuthenticator(tokenStore, ll)
	routeReg := loadRegistry(ctx, ll, oauthValid)

	ll.Info("starting up holepunch cacher...")

	return cacher.StartService(ctx, *cacheArgs, ll, routeReg, tokenAuth)
}

func startXDSCmd(ctx context.Context, _ *cli.Command) error {
	ctx, stop, ll := defaultInit(ctx)
	defer stop()

	otelReq, shutdown := loadOTEL(ctx, ll)
	if otelReq {
		defer otelShutdown(ctx, ll, shutdown)
	}

	sessionStore := loadSessionStore(ctx, ll)
	oauthValid := loadOauthMngr(sessionStore, ll)

	routeReg := loadRegistry(ctx, ll, oauthValid)

	ll.Info("starting up holepunch envoy-xds...")

	go manageRegistryRefresh(ctx, routeReg)

	return envoy.RunServer(ctx, ll, routeReg, *tokenSvcArgs, *webArgs, *xdsArgs)
}

//

func defaultInit(ctx context.Context) (context.Context, context.CancelFunc, logs.Logger) {
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	ll := loadLogging()

	if globalArgs.Development {
		ll.Warn("running in development mode")
	}

	return ctx, stop, ll
}

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
