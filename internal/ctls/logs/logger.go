package logs

import (
	"context"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

type logger struct {
	s         *slog.Logger
	spanAttrs []attribute.KeyValue
}

func (l logger) Debug(msg string, attr ...slog.Attr) {
	l.s.LogAttrs(context.Background(), slog.LevelDebug, msg, attr...)
}

func (l logger) DebugCtx(ctx context.Context, msg string, attr ...slog.Attr) {
	l.logWithOTel(ctx, slog.LevelDebug, "log.debug", msg, attr...)
}

func (l logger) Debugf(format string, args ...interface{}) {
	l.s.LogAttrs(context.Background(), slog.LevelDebug, fmt.Sprintf(format, args...))
}

func (l logger) Info(msg string, attr ...slog.Attr) {
	l.s.LogAttrs(context.Background(), slog.LevelInfo, msg, attr...)
}

func (l logger) InfoCtx(ctx context.Context, msg string, attr ...slog.Attr) {
	l.logWithOTel(ctx, slog.LevelInfo, "log.info", msg, attr...)
}

func (l logger) Infof(format string, args ...interface{}) {
	l.s.LogAttrs(context.Background(), slog.LevelInfo, fmt.Sprintf(format, args...))
}

func (l logger) Warn(msg string, attr ...slog.Attr) {
	l.s.LogAttrs(context.Background(), slog.LevelWarn, msg, attr...)
}

func (l logger) WarnCtx(ctx context.Context, msg string, attr ...slog.Attr) {
	l.logWithOTel(ctx, slog.LevelWarn, "log.warn", msg, attr...)
}

func (l logger) Warnf(format string, args ...interface{}) {
	l.s.LogAttrs(context.Background(), slog.LevelWarn, fmt.Sprintf(format, args...))
}

func (l logger) Error(msg string, attr ...slog.Attr) {
	l.s.LogAttrs(context.Background(), slog.LevelError, msg, attr...)
}

func (l logger) ErrorCtx(ctx context.Context, msg string, attr ...slog.Attr) {
	l.logWithOTel(ctx, slog.LevelError, "log.error", msg, attr...)
}

func (l logger) Errorf(format string, args ...interface{}) {
	l.s.LogAttrs(context.Background(), slog.LevelError, fmt.Sprintf(format, args...))
}

func (l logger) StringArg(k, v string) slog.Attr {
	return slog.String(k, v)
}

func (l logger) IntArg(k string, v int) slog.Attr {
	return slog.Int(k, v)
}

func (l logger) With(attrs []slog.Attr) Logger {
	out := make([]any, 0, 2*len(attrs))
	for _, a := range attrs {
		out = append(out, a.Key, a.Value.Any())
	}

	return logger{
		s:         l.s.With(out...),
		spanAttrs: append(l.spanAttrs, slogAttrsToOTel(attrs)...),
	}
}

func (l logger) StartSpan(ctx context.Context, name string) (context.Context, func()) {
	// Only create spans if we have a real (non-noop) tracer provider.
	parent := trace.SpanFromContext(ctx)
	if parent == nil || parent.TracerProvider() == noop.NewTracerProvider() {
		return ctx, func() {}
	}

	tr := parent.TracerProvider().Tracer("logs")

	// If a valid parent span is present in ctx, this will be a nested child span.
	// If ctx has no valid span (but has a real provider), this becomes a root span.
	ctx, span := tr.Start(ctx, name)
	if len(l.spanAttrs) > 0 {
		span.SetAttributes(l.spanAttrs...)
	}

	return ctx, func() { span.End() }
}
