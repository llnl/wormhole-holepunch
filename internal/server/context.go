package server

import (
	"context"
	"net/http"

	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
)

type contextKey string

const (
	loggerKey contextKey = "logger"
)

func setLogger(r *http.Request, ll logs.Logger) *http.Request {
	ctx := context.WithValue(r.Context(), loggerKey, ll)
	return r.WithContext(ctx)
}

// mustGetLogger retrieves the logger from the request context.
func mustGetLogger(ctx context.Context) logs.Logger {
	//nolint:forcetypeassert
	return ctx.Value(loggerKey).(logs.Logger)
}
