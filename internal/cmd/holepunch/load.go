package holepunch

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/ctls/aescipher"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
	"github.com/llnl/wormhole-holepunch/internal/ctls/streams"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr"
	"github.com/llnl/wormhole-holepunch/internal/wormhole/registry"
	"github.com/llnl/wormhole-holepunch/internal/wormhole/token"
)

func loadAuthenticator(kvStore streams.KVStore, ll logs.Logger) token.Authenticator {
	cipher, err := aescipher.New(args.GetValueOrFile(tokenSvcArgs.TokenCipherKey))
	if err != nil {
		log.Fatalf("failed to load aescipher: %s", err.Error())
	}

	return token.Initialize(cipher, kvStore, ll, *tokenSvcArgs)
}

func loadLogging() logs.Logger {
	ll, err := logs.Initialize(*loggingArgs)
	if err != nil {
		log.Fatal(err)
	}

	return ll
}

func loadOauthMngr(
	kvStore streams.KVStore,
	ll logs.Logger,
) oauthmngr.Validator {
	oauthValid, err := oauthmngr.Initialize(kvStore, ll, *oauthArgs)
	if err != nil {
		log.Fatalf("failed to init oauth manager: %s", err.Error())
	}

	return oauthValid
}

func loadOTEL(
	ctx context.Context,
	ll logs.Logger,
) (bool, func(context.Context) error) {
	if loggingArgs.OtelEndpoint == "" {
		return false, nil
	}

	shutdown, err := logs.InitOTel(ctx, *loggingArgs)
	if err != nil {
		log.Fatalf("failed to init OTEL: %s", err.Error())
	}

	ll.Info(fmt.Sprintf(
		"connected to OTEL endpoint %s (%s)",
		loggingArgs.OtelEndpoint,
		loggingArgs.OtelService,
	))

	return true, shutdown
}

func loadRegistry(
	ctx context.Context,
	ll logs.Logger,
	oauthValid oauthmngr.Validator,
) registry.Router {
	routes, err := registry.Initialize(
		ctx,
		requests.DefaultClient(ll),
		oauthValid,
		loadRoutePubSub(ctx, ll),
		*routeRegArgs,
		ll,
	)
	if err != nil {
		log.Fatal(err)
	}

	return routes
}

func loadRoutePubSub(
	ctx context.Context,
	ll logs.Logger,
) streams.PubSub {
	ctls, err := streams.InitializeRoutes(ctx, *storageArgs, ll)
	if err != nil {
		log.Fatalf("failed to load route stream: %s", err.Error())
	}

	return ctls
}

func loadTokenStore(
	ctx context.Context,
	ll logs.Logger,
) streams.KVStore {
	ctls, err := streams.InitializeTokens(ctx, *storageArgs, ll)
	if err != nil {
		log.Fatalf("failed to load route stream: %s", err.Error())
	}

	return ctls
}

func loadSessionStore(
	ctx context.Context,
	ll logs.Logger,
) streams.KVStore {
	ctls, err := streams.InitializeSessions(ctx, *storageArgs, ll, time.Duration(oauthArgs.NonceTTL))
	if err != nil {
		log.Fatalf("failed to load route stream: %s", err.Error())
	}

	return ctls
}
