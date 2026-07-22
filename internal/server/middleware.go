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
)

// nolint: contextcheck
func (d *data) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := newResponseWriter(w)

		if r.URL.String() == defaultPrefix+"healthz" {
			next.ServeHTTP(rw, r)
			return
		}

		// Build request logger
		ll := d.ll.With(
			[]slog.Attr{
				slog.String("req."+keys.RequestIDHeader, r.Header.Get(keys.RequestIDHeader)),
				slog.String("req.method", r.Method),
				slog.String("req.path", r.URL.String()),
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
		r = setLogger(r, ll)

		ll.DebugCtx(r.Context(), "inbound request")

		next.ServeHTTP(rw, r)

		ll.DebugCtx(
			r.Context(),
			"request completed",
			ll.IntArg("status", rw.status),
			ll.StringArg("duration", time.Since(start).String()),
		)
	})
}

func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//nolint:contextcheck
		defer func() {
			if err := recover(); err != nil {
				ll := mustGetLogger(r.Context())
				ll.Error("recovered from panic: " + fmt.Sprint(err))

				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		}()

		next.ServeHTTP(w, r)
	})
}
