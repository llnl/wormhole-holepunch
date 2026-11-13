package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/paths"
)

// ledgerServer returns the handler exactly as LedgerAPI serves it, middleware included.
func ledgerServer(callback http.Handler) http.Handler {
	ll := logs.InitializeDiscard()
	c := Configuration{Address: ":0"}

	return c.initializeAdminServer(&data{ll: ll, cfg: c}, ledgerHandlers(callback)).Handler
}

func Test_ledgerHandlers(t *testing.T) {
	callback := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})

	serve := func(method, path string) int {
		rec := httptest.NewRecorder()
		ledgerServer(callback).ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader("")))

		return rec.Code
	}

	t.Run("callback reaches the handler", func(t *testing.T) {
		assert.Equal(t, http.StatusTeapot, serve(http.MethodGet, paths.CallbackPrefix+"?nonce=n"))
	})

	t.Run("health and version", func(t *testing.T) {
		assert.Equal(t, http.StatusOK, serve(http.MethodGet, paths.HealthPath))
		assert.Equal(t, http.StatusOK, serve(http.MethodGet, paths.VersionPath))
	})

	t.Run("admin endpoints are not exposed", func(t *testing.T) {
		assert.Equal(t, http.StatusNotFound, serve(http.MethodGet, paths.ControlsPath))
		assert.Equal(t, http.StatusNotFound, serve(http.MethodPost, paths.InvalidateWebhookPath))
	})
}
