package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/paths"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr/ledger"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr/oauthapi"
)

type stubLedger struct {
	captured oauthapi.CaptureRequest
}

func (s *stubLedger) Capture(_ context.Context, req oauthapi.CaptureRequest) (oauthapi.CaptureResponse, error) {
	s.captured = req

	return oauthapi.CaptureResponse{CallbackURL: "https://foo.example.com/-/wormhole/oauthmngr?nonce=n"}, nil
}

func (*stubLedger) Redeem(context.Context, oauthapi.RedeemRequest) (oauthapi.RedeemResponse, error) {
	return oauthapi.RedeemResponse{}, ledger.ErrFlowUnavailable
}

// ledgerServer returns the handler exactly as LedgerAPI serves it, middleware included.
func ledgerServer(flowLedger ledger.Ledger) http.Handler {
	ll := logs.InitializeDiscard()
	c := Configuration{Address: ":0"}

	return c.initializeAdminServer(&data{ll: ll, cfg: c}, ledgerHandlers(ll, flowLedger)).Handler
}

func Test_ledgerHandlers(t *testing.T) {
	serve := func(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))

		return rec
	}

	t.Run("capture reaches the ledger", func(t *testing.T) {
		stub := &stubLedger{}

		rec := serve(ledgerServer(stub), http.MethodPost, paths.CapturePath,
			`{"nonce":"n","client_ip":"10.0.0.1","authority":"auth.example.com","session_cookie":"c"}`)

		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "c", stub.captured.SessionCookie)

		var resp oauthapi.CaptureResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		assert.Equal(t, "https://foo.example.com/-/wormhole/oauthmngr?nonce=n", resp.CallbackURL)
	})

	t.Run("redeem failures map to forbidden", func(t *testing.T) {
		rec := serve(ledgerServer(&stubLedger{}), http.MethodPost, paths.RedeemPath, `{"nonce":"n"}`)

		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("health and version", func(t *testing.T) {
		h := ledgerServer(&stubLedger{})

		assert.Equal(t, http.StatusOK, serve(h, http.MethodGet, paths.HealthPath, "").Code)
		assert.Equal(t, http.StatusOK, serve(h, http.MethodGet, paths.VersionPath, "").Code)
	})

	t.Run("admin endpoints are not exposed", func(t *testing.T) {
		h := ledgerServer(&stubLedger{})

		assert.Equal(t, http.StatusNotFound, serve(h, http.MethodGet, paths.ControlsPath, "").Code)
		assert.Equal(t, http.StatusNotFound, serve(h, http.MethodPost, paths.InvalidateWebhookPath, "{}").Code)
	})

	t.Run("ledger endpoints only accept POST", func(t *testing.T) {
		assert.Equal(t, http.StatusMethodNotAllowed,
			serve(ledgerServer(&stubLedger{}), http.MethodGet, paths.CapturePath, "").Code)
	})
}
