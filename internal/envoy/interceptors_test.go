package envoy

import (
	"context"
	"net"
	"testing"

	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	tracetest "go.opentelemetry.io/otel/sdk/trace/tracetest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
)

func Test_unaryTracingInterceptor(t *testing.T) {
	t.Parallel()

	t.Run("start span status ok", func(t *testing.T) {
		sr := tracetest.NewSpanRecorder()
		tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
		otel.SetTracerProvider(tp)
		defer func() { _ = tp.Shutdown(context.Background()) }()

		base := logs.InitializeDiscard()

		interceptor := unaryTracingInterceptor(base, "test-tracer")

		ctx := metadata.NewIncomingContext(t.Context(), metadata.MD{"x-request-id": {"rid-1"}})
		ctx = peer.NewContext(ctx, &peer.Peer{Addr: &net.IPAddr{IP: net.ParseIP("127.0.0.1")}})

		info := &grpc.UnaryServerInfo{FullMethod: "/pkg.Svc/DoThing"}

		handler := func(ctx context.Context, req any) (any, error) {
			return "ok", nil
		}

		resp, err := interceptor(ctx, "req", info, handler)
		spans := sr.Ended()

		assert.Equal(t, "ok", resp)
		assert.NoError(t, err)
		assert.Len(t, spans, 1)

		var (
			hasRPCSystem bool
			hasGRPCCode  bool
		)

		for _, a := range spans[0].Attributes() {
			if a.Key == "rpc.system" && a.Value.AsString() == "grpc" {
				hasRPCSystem = true
			}

			if a.Key == "rpc.grpc.status_code" {
				hasGRPCCode = true
			}
		}

		assert.True(t, hasRPCSystem, "rpc.system")
		assert.True(t, hasGRPCCode, "rpc.grpc.status_code")
	})

	t.Run("set status and record error", func(t *testing.T) {
		sr := tracetest.NewSpanRecorder()
		tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
		otel.SetTracerProvider(tp)
		defer func() { _ = tp.Shutdown(context.Background()) }()

		base := logs.InitializeDiscard()
		interceptor := unaryTracingInterceptor(base, "test-tracer")

		info := &grpc.UnaryServerInfo{FullMethod: "/pkg.Svc/DoThing"}

		wantErr := status.Error(13 /* Internal */, "boom")

		handler := func(ctx context.Context, req any) (any, error) {
			return nil, wantErr
		}

		_, err := interceptor(t.Context(), "req", info, handler)
		spans := sr.Ended()

		assert.Error(t, err)
		assert.Len(t, spans, 1)

		var hasGRPCCode bool

		for _, v := range spans[0].Attributes() {
			if v.Key == "rpc.grpc.status_code" {
				hasGRPCCode = true
			}
		}

		assert.True(t, hasGRPCCode, "rpc.grpc.status_code")
	})
}

func Test_authLogger(t *testing.T) {
	t.Parallel()

	t.Run("no span found", func(t *testing.T) {
		s := &authServer{ll: logs.InitializeDiscard()}

		reqID := "rid-123"
		req := &auth.CheckRequest{
			Attributes: &auth.AttributeContext{
				Request: &auth.AttributeContext_Request{
					Http: &auth.AttributeContext_HttpRequest{
						Method: "GET",
						Path:   "/x",
						Host:   "example",
						Headers: map[string]string{
							keys.RequestIDHeader: reqID,
							keys.PikoHeader:      "piko",
						},
					},
				},
			},
		}

		ctx := metadata.NewIncomingContext(t.Context(), metadata.MD{
			"x-request-id": {reqID},
		})

		ctx2, _, end := s.authLogger(ctx, req)

		// It should return a context; and end func should end a span (so we see it recorded).
		if ctx2 == nil {
			assert.NotNil(t, ctx2)
		}
		end()
	})
}

func Test_metadataCarrier(t *testing.T) {
	t.Parallel()

	md := metadata.MD{
		"a": []string{"1", "2"},
		"b": []string{"x"},
	}

	c := metadataCarrier(md)

	if got := c.Get("a"); got != "1" {
		t.Fatalf("Get(a)=%q, want %q", got, "1")
	}

	c.Set("c", "z")
	if got := metadata.MD(c).Get("c"); len(got) != 1 || got[0] != "z" {
		t.Fatalf("Set(c,z) => %v, want [z]", got)
	}

	keys := c.Keys()
	if len(keys) != 3 {
		t.Fatalf("Keys() len=%d, want 3 (keys=%v)", len(keys), keys)
	}
}

func Test_first(t *testing.T) {
	t.Parallel()

	assert.Empty(t, first(nil))
	assert.Empty(t, first([]string{}))
	assert.Equal(t, "a", first([]string{"a", "b"}))
}
