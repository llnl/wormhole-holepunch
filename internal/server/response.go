package server

import "net/http"

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
