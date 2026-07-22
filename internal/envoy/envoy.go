package envoy

import (
	"context"
	"errors"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
)

// newGrpcServer established a gRPC with no service registered, using default options pre-established
// for all potential Holepunch requirements. Note that we do not establish any sort of authorization
// or mTLS requirements for this server at this time. It is assumed that the deployment is controlled
// via the Helm chart and these services will not be exposed to users. If defense in depth is a
// requirement deployment as part of a service mesh (e.g., Istio) is the only current option.
func newGrpcServer(ll logs.Logger, webArgs args.WebServer) *grpc.Server {
	grpcOptions := []grpc.ServerOption{
		grpc.UnaryInterceptor(unaryTracingInterceptor(ll, "envoy/authz")),
		// Set some initial bounds for concurrent requests. These may need
		// refined in the future.
		grpc.MaxConcurrentStreams(webArgs.GRPCMaxConcurrentStreams),
		grpc.MaxRecvMsgSize(webArgs.MaxRecvMsgSize),
		grpc.MaxSendMsgSize(webArgs.MaxSendMsgSize),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    webArgs.GRPCKeepaliveTime,
			Timeout: webArgs.GRPCKeepaliveTimeout,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             webArgs.GRPCKeepaliveMinTime,
			PermitWithoutStream: true,
		}),
	}

	return grpc.NewServer(grpcOptions...)
}

func runServer(
	ctx context.Context,
	ll logs.Logger,
	grpcServer *grpc.Server,
	lis net.Listener,
) error {
	// Channel to monitor server errors
	errChan := make(chan error, 1)

	go func() {
		ll.Info("gRPC server starting")

		err := grpcServer.Serve(lis)
		if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			ll.Error("gRPC server encountered an error: " + err.Error())

			errChan <- err
		}

		close(errChan) // Ensure to close the channel on server exit
	}()

	// Handle context cancellation and graceful shutdown
	return waitForShutdown(ctx, ll, grpcServer, errChan)
}

func waitForShutdown(
	ctx context.Context,
	ll logs.Logger,
	grpcServer *grpc.Server,
	errChan <-chan error,
) error {
	select {
	case <-ctx.Done():
		// Context canceled, initiate graceful shutdown
		ll.Info("context canceled, shutting down gRPC server...")

		grpcServer.GracefulStop()
	case err := <-errChan:
		if err != nil {
			ll.Error("server error occurred: " + err.Error())
			return err
		}
	}

	ll.Info("gRPC server shut down gracefully")

	return nil
}
