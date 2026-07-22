package logs

import (
	"context"
	"log/slog"
	"time"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// InitOTel should be used to initialize the open telemetry exporter in advance of using
// the functions within the Logger interface that need to retrieve a valid SpanFromContext.
// At this time we do not consider OTEL collectors to be our primary logging mechanism;
// however; it is possible to discard standard logging and rely on this is needed.
func InitOTel(
	ctx context.Context,
	loggingArgs args.Logging,
) (func(context.Context) error, error) {
	expOpts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(loggingArgs.OtelEndpoint),
	}

	if loggingArgs.OtelInsecure {
		expOpts = append(expOpts, otlptracegrpc.WithInsecure())
	}

	exp, err := otlptracegrpc.New(ctx, expOpts...)
	if err != nil {
		return nil, err
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(loggingArgs.OtelService),
		),
	)
	if err != nil {
		return nil, err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithBatcher(exp),
	)
	otel.SetTracerProvider(tp)

	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return tp.Shutdown, nil
}

//

func (l logger) logWithOTel(
	ctx context.Context,
	level slog.Level,
	spanName string,
	msg string,
	attrs ...slog.Attr,
) {
	defer l.s.LogAttrs(ctx, level, msg, attrs...)

	span := trace.SpanFromContext(ctx)
	hasValidSpan := span != nil && span.SpanContext().IsValid()

	// Only create a span if there isn't already one in ctx.
	if !hasValidSpan {
		tracer := otel.Tracer("logs") // or your provider if you have one

		var newSpan trace.Span

		ctx, newSpan = tracer.Start(ctx, spanName)
		defer newSpan.End()

		span = newSpan
	}

	// If we have a valid span (existing or new), annotate it.
	if span != nil && span.SpanContext().IsValid() {
		span.SetAttributes(
			attribute.String("log.severity", level.String()),
			attribute.String("log.message", msg),
		)
		span.SetAttributes(slogAttrsToOTel(attrs)...)
	}

	addSpanEventFromLog(ctx, level, msg, attrs)
}

func addSpanEventFromLog(ctx context.Context, level slog.Level, msg string, attrs []slog.Attr) {
	span := trace.SpanFromContext(ctx)
	if span == nil || !span.SpanContext().IsValid() {
		return
	}

	otelAttrs := make([]attribute.KeyValue, 0, len(attrs)+2)
	otelAttrs = append(otelAttrs,
		attribute.String("log.severity", level.String()),
		attribute.String("log.message", msg),
	)
	otelAttrs = append(otelAttrs, slogAttrsToOTel(attrs)...)

	span.AddEvent("log", trace.WithAttributes(otelAttrs...))

	// Opinionated: mark span status on error logs.
	if level >= slog.LevelError {
		span.SetStatus(codes.Error, msg)
	}
}

func slogAttrsToOTel(attrs []slog.Attr) []attribute.KeyValue {
	out := make([]attribute.KeyValue, 0, len(attrs))
	for _, a := range attrs {
		k := attribute.Key(a.Key)

		switch a.Value.Kind() {
		case slog.KindString:
			out = append(out, k.String(a.Value.String()))
		case slog.KindBool:
			out = append(out, k.Bool(a.Value.Bool()))
		case slog.KindInt64:
			out = append(out, k.Int64(a.Value.Int64()))
		case slog.KindUint64:
			out = append(out, k.Int64(int64(a.Value.Uint64()))) //nolint: gosec
		case slog.KindFloat64:
			out = append(out, k.Float64(a.Value.Float64()))
		case slog.KindDuration:
			out = append(out, k.String(a.Value.Duration().String()))
		case slog.KindTime:
			out = append(out, k.String(a.Value.Time().Format(time.RFC3339Nano)))
		default:
			out = append(out, k.String(a.Value.String()))
		}
	}

	return out
}
