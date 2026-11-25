package logs

import (
	"context"
)

type contextKey struct{}

// NewContext returns a copy of ctx carrying ll, typically a request-scoped logger.
func NewContext(ctx context.Context, ll Logger) context.Context {
	return context.WithValue(ctx, contextKey{}, ll)
}

// FromContext returns the logger stored in ctx, or fallback when none is present.
func FromContext(ctx context.Context, fallback Logger) Logger {
	if ll, ok := ctx.Value(contextKey{}).(Logger); ok && ll != nil {
		return ll
	}

	return fallback
}

// MustFromContext returns the logger stored in ctx and panics when none is present.
func MustFromContext(ctx context.Context) Logger {
	ll := FromContext(ctx, nil)
	if ll == nil {
		panic("logs: no logger in context")
	}

	return ll
}
