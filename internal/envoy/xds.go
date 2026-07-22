package envoy

import (
	"context"
	"net"
	"time"

	clusterservice "github.com/envoyproxy/go-control-plane/envoy/service/cluster/v3"
	discoverygrpc "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	endpointservice "github.com/envoyproxy/go-control-plane/envoy/service/endpoint/v3"
	listenerservice "github.com/envoyproxy/go-control-plane/envoy/service/listener/v3"
	routeservice "github.com/envoyproxy/go-control-plane/envoy/service/route/v3"
	runtimeservice "github.com/envoyproxy/go-control-plane/envoy/service/runtime/v3"
	secretservice "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	srv "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"github.com/envoyproxy/go-control-plane/pkg/test/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/wormhole/registry"
)

var (
	refreshTicker = 30 * time.Second
)

type xdsServer struct {
	cache        cache.SnapshotCache
	ll           logs.Logger
	routeReg     registry.Router
	tokenSvcArgs args.TokenService
	xds          srv.Server
	xdsArgs      args.XDS
}

func RunServer(
	ctx context.Context,
	ll logs.Logger,
	routeReg registry.Router,
	tokenSvcArgs args.TokenService,
	webArgs args.WebServer,
	xdsArgs args.XDS,
) error {
	ll.Info("starting xds management server on " + webArgs.ServerAddress)

	lis, err := net.Listen("tcp", webArgs.ServerAddress)
	if err != nil {
		ll.Error("failed to listen: " + err.Error())
		return err
	}

	cache := cache.NewSnapshotCache(false, cache.IDHash{}, ll)
	grpcServer := newGrpcServer(ll, webArgs)

	s := &xdsServer{
		cache:        cache,
		ll:           ll,
		routeReg:     routeReg,
		tokenSvcArgs: tokenSvcArgs,
		xds:          srv.NewServer(ctx, cache, &test.Callbacks{}),
		xdsArgs:      xdsArgs,
	}

	if err = s.initSnapshot(ctx); err != nil {
		ll.Error("unable to initialize snapshot: " + err.Error())
		return err
	}

	s.registerServer(grpcServer)

	// Register health service.
	hs := health.NewServer()
	grpc_health_v1.RegisterHealthServer(grpcServer, hs)
	hs.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)

	go s.manageRefresh(ctx)

	return runServer(ctx, ll, grpcServer, lis)
}

//

func (s *xdsServer) registerServer(grpcServer *grpc.Server) {
	discoverygrpc.RegisterAggregatedDiscoveryServiceServer(grpcServer, s.xds)
	endpointservice.RegisterEndpointDiscoveryServiceServer(grpcServer, s.xds)
	clusterservice.RegisterClusterDiscoveryServiceServer(grpcServer, s.xds)
	routeservice.RegisterRouteDiscoveryServiceServer(grpcServer, s.xds)
	listenerservice.RegisterListenerDiscoveryServiceServer(grpcServer, s.xds)
	secretservice.RegisterSecretDiscoveryServiceServer(grpcServer, s.xds)
	runtimeservice.RegisterRuntimeDiscoveryServiceServer(grpcServer, s.xds)
}

func (s *xdsServer) manageRefresh(ctx context.Context) {
	s.refreshSnapshot(ctx)

	ticker := time.NewTicker(refreshTicker)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.refreshSnapshot(ctx)
		}
	}
}
