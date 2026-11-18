package server

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/paths"
)

// LoggingMiddleware stores a request-scoped logger (see logs.FromContext) carrying request
// metadata, starts a server span when tracing is enabled, and logs each completed request.
//
// nolint: contextcheck
func LoggingMiddleware(base logs.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SetDefaultHeaders(w)

		start := time.Now()
		rw := newResponseWriter(w)

		if r.URL.Path == paths.HealthPath {
			next.ServeHTTP(rw, r)
			return
		}

		// Build request logger
		ll := base.With(
			[]slog.Attr{
				slog.String("req."+keys.RequestIDHeader, r.Header.Get(keys.RequestIDHeader)),
				slog.String("req.method", r.Method),
				// Path only: query strings may carry secrets (e.g., the oauth callback nonce).
				slog.String("req.path", r.URL.Path),
				slog.String("req.remote-address", r.RemoteAddr),
				slog.String("req.host", r.Host),
			},
		)

		span := trace.SpanFromContext(r.Context())

		endSpan := func() {}

		ctx := r.Context()

		if span.TracerProvider() != noop.NewTracerProvider() {
			tr := otel.Tracer("holepunch-admin")

			ctx, span = tr.Start(
				r.Context(),
				r.Method+" "+r.URL.Path,
				trace.WithSpanKind(trace.SpanKindServer),
			)

			endSpan = func() {
				span.End()
			}
		} else {
			ll.Debug("no span in context")
		}

		defer endSpan()

		r = r.WithContext(ctx)

		// Put logger in request context (now includes the span ctx, if started)
		r = r.WithContext(logs.NewContext(r.Context(), ll))

		ll.DebugCtx(r.Context(), "inbound request")

		next.ServeHTTP(rw, r)

		ll.InfoCtx(
			r.Context(),
			"request completed",
			ll.IntArg("status", rw.status),
			ll.StringArg("duration", time.Since(start).String()),
		)
	})
}

// RecoveryMiddleware converts handler panics into 500 responses. It requires a logger in
// the request context, so it must be wrapped by LoggingMiddleware.
func RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//nolint:contextcheck
		defer func() {
			if err := recover(); err != nil {
				ll := logs.MustFromContext(r.Context())
				ll.Error("recovered from panic: " + fmt.Sprint(err))

				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		}()

		next.ServeHTTP(w, r)
	})
}
