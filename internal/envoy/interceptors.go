package envoy

import (
	"context"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
)

const healthCheckMethod = "/grpc.health.v1.Health/Check"

// unaryTracingInterceptor creates a per-request server span and ensures:
//   - parent context is extracted from inbound gRPC metadata (Envoy-forwarded trace headers)
//   - span status + grpc status code are recorded
//   - context is injected into outbound calls via a chained client interceptor
//
// nolint: funlen
func unaryTracingInterceptor(base logs.Logger, name string) grpc.UnaryServerInterceptor {
	tr := otel.Tracer(name)
	prop := otel.GetTextMapPropagator()

	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if info.FullMethod == healthCheckMethod {
			return handler(ctx, req)
		}

		start := time.Now()

		attrs := []slog.Attr{slog.String("grpc.method", info.FullMethod)}

		if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
			attrs = append(attrs, slog.String("req.remote-address", p.Addr.String()))
		}

		var reqID string
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			reqID = first(md.Get("x-request-id"))
			if reqID != "" {
				attrs = append(attrs, slog.String("req.x-request-id", reqID))
			}
		}

		ll := base.With(attrs)

		// Extract parent trace context from inbound metadata, Envoy should forward.
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			ctx = prop.Extract(ctx, metadataCarrier(md))
		}

		ctx, span := tr.Start(
			ctx,
			info.FullMethod,
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				attribute.String("rpc.system", "grpc"),
			),
		)
		defer span.End()

		if reqID != "" {
			span.SetAttributes(attribute.String("http.request_id", reqID))
		}

		if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
			span.SetAttributes(attribute.String("net.peer.addr", p.Addr.String()))
		}

		// Make this span context available to logs that understand context.
		ll.DebugCtx(ctx, "inbound request")

		resp, err := handler(ctx, req)

		// Identify completed status for span.
		st := status.Convert(err)
		span.SetAttributes(attribute.Int("rpc.grpc.status_code", int(st.Code())))

		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, st.Message())
		} else {
			span.SetStatus(codes.Ok, "OK")
		}

		ll.InfoCtx(
			ctx,
			"request completed",
			ll.StringArg("duration", time.Since(start).String()),
			ll.StringArg("grpc.code", st.Code().String()),
		)

		return resp, err
	}
}

//

type metadataCarrier metadata.MD

func (c metadataCarrier) Get(key string) string {
	md := metadata.MD(c)
	return first(md.Get(key))
}
func (c metadataCarrier) Set(key, value string) {
	md := metadata.MD(c)
	md.Set(key, value)
}
func (c metadataCarrier) Keys() []string {
	md := metadata.MD(c)
	out := make([]string, 0, len(md))

	for k := range md {
		out = append(out, k)
	}

	return out
}

func first(vs []string) string {
	if len(vs) == 0 {
		return ""
	}

	return vs[0]
}
