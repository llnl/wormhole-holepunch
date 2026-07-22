package server

import (
	"context"
	"net/http"
	"time"

	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/rules"
	"github.com/llnl/wormhole-holepunch/internal/wormhole/registry"
	"github.com/llnl/wormhole-holepunch/internal/wormhole/token"
)

const (
	readTimeout       = 10 * time.Second
	writeTimeout      = 10 * time.Second
	readHeaderTimeout = 5 * time.Second
)

type Configuration struct {
	Address string
}

type data struct {
	cfg       Configuration
	ll        logs.Logger
	routeReg  registry.Router
	tokenAuth token.Authenticator
	vv        rules.Validator
}

func (c Configuration) AdminAPI(
	ctx context.Context,
	ll logs.Logger,
	routeReg registry.Router,
	tokenAuth token.Authenticator,
) error {
	ll.Info("starting admin server on " + c.Address)

	d := &data{
		ll:        ll,
		cfg:       c,
		routeReg:  routeReg,
		tokenAuth: tokenAuth,
		vv:        rules.NewValidator(),
	}

	srv := c.initializeAdminServer(d, d.adminHandlers())

	return runServer(ctx, ll, srv)
}

//

func (c Configuration) initializeAdminServer(d *data, mux http.Handler) *http.Server {
	return &http.Server{
		Addr:              c.Address,
		Handler:           d.loggingMiddleware(recoveryMiddleware(mux)),
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		ReadHeaderTimeout: readHeaderTimeout,
	}
}

//

func runServer(ctx context.Context, ll logs.Logger, srv *http.Server) error {
	// Channel to monitor server errors
	errChan := make(chan error, 1)

	go func() {
		ll.Info("HTTP server starting")

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			ll.Error("HTTP server encountered an error: " + err.Error())

			errChan <- err
		}

		close(errChan) // Close channel when server exits
	}()

	// Handle context cancellation and graceful shutdown
	return waitForShutdown(ctx, ll, srv, errChan)
}

func waitForShutdown(ctx context.Context, ll logs.Logger, srv *http.Server, errChan <-chan error) error {
	select {
	case <-ctx.Done():
		// Context canceled, initiate graceful shutdown
		ll.Info("context canceled, shutting down HTTP server...")

		shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			ll.Error("error during HTTP server shutdown: " + err.Error())
			return err
		}
	case err := <-errChan:
		if err != nil {
			ll.Error("server error occurred: " + err.Error())
			return err
		}
	}

	ll.Info("HTTP server shut down gracefully")

	return nil
}
