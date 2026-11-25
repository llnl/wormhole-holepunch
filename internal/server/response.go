package server

import (
	"net/http"

	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
)

// SetDefaultHeaders sets the security headers used on every HTTP API response.
func SetDefaultHeaders(w http.ResponseWriter) {
	w.Header().Set(keys.CacheControlHeader, "no-store")
	w.Header().Set(keys.ReferrerPolicyHeader, "no-referrer")
	w.Header().Set(keys.ContentTypeOptionsHeader, "nosniff")
}

// responseWriter is a wrapper around http.ResponseWriter
// that tracks the status code.
type responseWriter struct {
	http.ResponseWriter

	status int
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{
		ResponseWriter: w,

		status: http.StatusOK,
	}
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	rw.status = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}
