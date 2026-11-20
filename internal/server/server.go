package server

import (
	"context"
	"net/http"
	"time"

	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
)

const (
	readTimeout       = 10 * time.Second
	writeTimeout      = 10 * time.Second
	readHeaderTimeout = 5 * time.Second
)

// Configuration holds the listener settings shared by every Holepunch HTTP service.
type Configuration struct {
	Address string
}

// Serve runs handler behind the shared middleware until ctx is canceled, then shuts down
// gracefully.
func (c Configuration) Serve(ctx context.Context, ll logs.Logger, handler http.Handler) error {
	return runServer(ctx, ll, c.NewHTTPServer(ll, handler))
}

// NewHTTPServer wraps handler with default response headers, shared logging and recovery
// middleware, and the server timeouts used by every Holepunch HTTP service.
func (c Configuration) NewHTTPServer(ll logs.Logger, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              c.Address,
		Handler:           LoggingMiddleware(ll, RecoveryMiddleware(handler)),
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

		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
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
