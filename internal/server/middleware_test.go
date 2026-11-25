package server

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/paths"
)

// attrRecorder captures the attributes the logging middleware attaches to its request logger.
type attrRecorder struct {
	logs.Logger
	attrs []slog.Attr
}

func (a *attrRecorder) With(attrs []slog.Attr) logs.Logger {
	a.attrs = append(a.attrs, attrs...)
	return a.Logger.With(attrs)
}

func assertDefaultHeaders(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()

	assert.Equal(t, "no-store", rr.Header().Get(keys.CacheControlHeader))
	assert.Equal(t, "no-referrer", rr.Header().Get(keys.ReferrerPolicyHeader))
	assert.Equal(t, "nosniff", rr.Header().Get(keys.ContentTypeOptionsHeader))
}

//

func Test_loggingMiddleware_omitsQuery(t *testing.T) {
	rec := &attrRecorder{Logger: logs.InitializeDiscard()}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	rr := httptest.NewRecorder()
	LoggingMiddleware(rec, next).ServeHTTP(
		rr,
		httptest.NewRequest(http.MethodGet, paths.CallbackPrefix+"?nonce=secret", nil),
	)

	assertDefaultHeaders(t, rr)

	var logged string

	for _, a := range rec.attrs {
		if a.Key == "req.path" {
			logged = a.Value.String()
		}
	}

	assert.Equal(t, paths.CallbackPrefix, logged)
}
