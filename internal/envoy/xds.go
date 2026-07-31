package envoy

import (
	"context"
	"net"
	"time"

	mutation_rules "github.com/envoyproxy/go-control-plane/envoy/config/common/mutation_rules/v3"
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
	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/wormhole/registry"
)

var (
	refreshTicker = 30 * time.Second
)

type xdsServer struct {
	cache cache.SnapshotCache
	// defaultHeaders establishes default/static header behavior that applies to the start of
	// all requests. The primary goal is to remove headers that we will rely upon at future stages
	// regardless if they will be injected later or not. In the majority of cases we ensure the
	// 'set' overwrites any potential user value, but in the interest of caution we will make
	// sure these occur first on headers identified as critical.
	defaultRequestHeaders []*mutation_rules.HeaderMutation
	ll                    logs.Logger
	routeReg              registry.Router
	tokenSvcArgs          args.TokenService
	xds                   srv.Server
	xdsArgs               args.XDS
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
		cache:                 cache,
		defaultRequestHeaders: establishDefaultRequestHeaders(tokenSvcArgs),
		ll:                    ll,
		routeReg:              routeReg,
		tokenSvcArgs:          tokenSvcArgs,
		xds:                   srv.NewServer(ctx, cache, &test.Callbacks{}),
		xdsArgs:               xdsArgs,
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

//

func establishDefaultRequestHeaders(tokenSvcArgs args.TokenService) []*mutation_rules.HeaderMutation {
	mutations := []*mutation_rules.HeaderMutation{ //nolint:prealloc
		{
			Action: &mutation_rules.HeaderMutation_Remove{
				Remove: tokenSvcArgs.SubtokenHeader,
			},
		},
	}

	for _, header := range keys.DefaultRemovableHeaders() {
		mutations = append(mutations, &mutation_rules.HeaderMutation{
			Action: &mutation_rules.HeaderMutation_Remove{
				Remove: header,
			},
		})
	}

	return mutations
}
