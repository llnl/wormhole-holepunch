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

func loadAuthenticator(
	kvStore streams.KVStore,
	ll logs.Logger,
	oauth oauthmngr.Validator,
) token.Authenticator {
	cipher, err := aescipher.New(args.GetValueOrFile(tokenSvcArgs.TokenCipherKey))
	if err != nil {
		log.Fatalf("failed to load aescipher: %s", err.Error())
	}

	return token.Initialize(cipher, kvStore, ll, *tokenSvcArgs, oauth)
}

func loadLogging() logs.Logger {
	ll, err := logs.Initialize(*loggingArgs)
	if err != nil {
		log.Fatal(err)
	}

	return ll
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
	routePS streams.PubSub,
	opts ...registry.Option,
) registry.Router {
	routes, err := registry.Initialize(
		ctx,
		requests.DefaultClient(ll),
		routePS,
		*routeRegArgs,
		ll,
		opts...,
	)
	if err != nil {
		log.Fatal(err)
	}

	return routes
}

// sessionBucketTTL is the TTL of the KV bucket shared by middleware flows and host sessions.
// Each entry carries its own shorter per-key TTL, so the bucket TTL only has to cover the
// longest of them. Every process binding the bucket must use the same value, as each applies
// it on startup.
func sessionBucketTTL() time.Duration {
	return time.Duration(max(oauthArgs.CookieMaxAge, oauthArgs.NonceTTL)) * time.Second
}

// loadOauth establishes the configured OAuth strategy. Only the middleware strategy mints
// nonces, so the flow store is only initialized for it.
func loadOauth(
	ctx context.Context,
	ll logs.Logger,
	streamClient *streams.Client,
) oauthmngr.Validator {
	var sessionStore streams.KVStore

	if oauthArgs.Strategy == oauthmngr.StrategyOauth2ProxyMiddleware {
		var err error

		sessionStore, err = streamClient.InitializeSessions(ctx, sessionBucketTTL(), oauthArgs.FlowStoreMaxBytes)
		if err != nil {
			log.Fatalf("failed to initialize session store: %s", err.Error())
		}
	}

	validator, err := oauthmngr.Initialize(sessionStore, requests.DefaultClient(ll), ll, *oauthArgs)
	if err != nil {
		log.Fatalf("failed to initialize oauth: %s", err.Error())
	}

	return validator
}
