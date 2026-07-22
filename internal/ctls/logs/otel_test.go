package logs

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	tracetest "go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func Test_logger_logWithOTel(t *testing.T) {
	t.Parallel()

	t.Run("new span", func(t *testing.T) {
		sr := tracetest.NewSpanRecorder()
		tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
		otel.SetTracerProvider(tp)
		defer func() { _ = tp.Shutdown(context.Background()) }()

		ctx := context.Background()

		l := (InitializeDiscard()).(logger)

		l.logWithOTel(ctx, slog.LevelWarn, "mySpan", "warn-msg", slog.Int("n", 7))

		spans := sr.Ended()

		assert.Len(t, spans, 1)
		assert.Equal(t, "mySpan", spans[0].Name())
	})

	t.Run("existing span", func(t *testing.T) {
		sr := tracetest.NewSpanRecorder()
		tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
		otel.SetTracerProvider(tp)
		defer func() { _ = tp.Shutdown(context.Background()) }()

		tr := tp.Tracer("test")
		ctx, parent := tr.Start(context.Background(), "parent")

		l := (InitializeDiscard()).(logger)

		l.logWithOTel(ctx, slog.LevelInfo, "spanNameIgnored", "hello",
			slog.String("k", "v"),
		)

		parent.End()
		spans := sr.Ended()

		assert.Len(t, spans, 1)
		assert.Equal(t, "parent", spans[0].Name())
	})

	t.Run("no parent", func(t *testing.T) {
		var buf bytes.Buffer
		h := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
		l := logger{s: slog.New(h)}

		// Ensure there is no valid span in context.
		ctx := context.Background()

		// If trace.SpanFromContext returns a non-recording invalid span, this must still log.
		l.logWithOTel(ctx, slog.LevelInfo, "ignored", "hello", slog.String("k", "v"))

		out := buf.String()

		assert.Contains(t, out, "hello")
	})

}

func Test_addSpanEventFromLog(t *testing.T) {
	t.Parallel()

	t.Run("set status error", func(t *testing.T) {
		sr := tracetest.NewSpanRecorder()
		tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
		otel.SetTracerProvider(tp)
		defer func() { _ = tp.Shutdown(context.Background()) }()

		tr := tp.Tracer("test")
		ctx, span := tr.Start(context.Background(), "root")

		addSpanEventFromLog(ctx, slog.LevelInfo, "info-msg", []slog.Attr{slog.String("a", "b")})
		addSpanEventFromLog(ctx, slog.LevelError, "err-msg", []slog.Attr{slog.Int64("code", 5)})

		span.End()

		ended := sr.Ended()
		assert.Len(t, ended, 1)

		events := ended[0].Events()
		assert.Len(t, events, 2)
		assert.Equal(t, "log", events[0].Name)
		assert.Equal(t, "log", events[1].Name)
	})

	t.Run("no span panic", func(t *testing.T) {
		// No span in context; should be a no-op.
		addSpanEventFromLog(t.Context(), slog.LevelInfo, "hello", []slog.Attr{slog.String("k", "v")})
	})
}

func Test_slogAttrsToOTel(t *testing.T) {
	ts := time.Date(2025, 1, 2, 3, 4, 5, 6, time.UTC)
	d := 1500 * time.Millisecond

	attrs := []slog.Attr{
		slog.String("s", "x"),
		slog.Bool("b", true),
		slog.Int64("i64", -7),
		slog.Uint64("u64", 9),
		slog.Float64("f64", 1.25),
		slog.Duration("dur", d),
		slog.Time("t", ts),
		slog.Any("any", map[string]any{"k": "v"}), // default branch -> String()
	}

	kvs := slogAttrsToOTel(attrs)

	// Convert to map for easy lookup.
	got := map[string]string{}
	for _, kv := range kvs {
		got[string(kv.Key)] = kv.Value.Emit()
	}

	assert.Equal(t, "x", got["s"])
	assert.Equal(t, "true", got["b"])
	assert.Equal(t, "-7", got["i64"])
	assert.Equal(t, "9", got["u64"])
	assert.Equal(t, "1.25", got["f64"])
}
