package ledger

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/llnl/wormhole-holepunch/internal/ctls/paths"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr/oauthapi"
)

type stubLedger struct {
	captureErr error
	redeemErr  error
	gotCapture oauthapi.CaptureRequest
}

func (s *stubLedger) Capture(_ context.Context, req oauthapi.CaptureRequest) (oauthapi.CaptureResponse, error) {
	s.gotCapture = req
	if s.captureErr != nil {
		return oauthapi.CaptureResponse{}, s.captureErr
	}

	return oauthapi.CaptureResponse{TargetSubdomain: "foo.example.com", CallbackURL: "https://foo.example.com/cb"}, nil
}

func (s *stubLedger) Redeem(_ context.Context, _ oauthapi.RedeemRequest) (oauthapi.RedeemResponse, error) {
	if s.redeemErr != nil {
		return oauthapi.RedeemResponse{}, s.redeemErr
	}

	return oauthapi.RedeemResponse{SessionCookie: "s", TargetURL: "https://foo.example.com/app"}, nil
}

func serve(t *testing.T, l Ledger, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()

	rec := httptest.NewRecorder()
	NewHandler(l, ll).ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))

	return rec
}

func Test_LedgerHandler(t *testing.T) {
	t.Run("capture success", func(t *testing.T) {
		stub := &stubLedger{}

		rec := serve(t, stub, http.MethodPost, paths.CapturePath,
			`{"nonce":"n","client_ip":"10.0.0.1","authority":"auth.example.com","session_cookie":"c"}`)

		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
		assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
		assert.Equal(t, oauthapi.CaptureRequest{Nonce: "n", ClientIP: "10.0.0.1", Authority: "auth.example.com", SessionCookie: "c"}, stub.gotCapture)

		var resp oauthapi.CaptureResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		assert.Equal(t, "https://foo.example.com/cb", resp.CallbackURL)
	})

	t.Run("redeem success", func(t *testing.T) {
		rec := serve(t, &stubLedger{}, http.MethodPost, paths.RedeemPath, `{"nonce":"n"}`)

		require.Equal(t, http.StatusOK, rec.Code)

		var resp oauthapi.RedeemResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		assert.Equal(t, "s", resp.SessionCookie)
	})

	errorCases := map[string]struct {
		err  error
		code int
	}{
		"invalid request":  {err: ErrInvalidRequest, code: http.StatusBadRequest},
		"flow unavailable": {err: ErrFlowUnavailable, code: http.StatusForbidden},
		"binding mismatch": {err: ErrBindingMismatch, code: http.StatusForbidden},
		"unexpected error": {err: errors.New("boom"), code: http.StatusInternalServerError},
	}

	for name, tc := range errorCases {
		t.Run(name, func(t *testing.T) {
			rec := serve(t, &stubLedger{redeemErr: tc.err}, http.MethodPost, paths.RedeemPath, `{"nonce":"n"}`)

			assert.Equal(t, tc.code, rec.Code)
			assert.Empty(t, rec.Body.String(), "no session details on failure")
		})
	}

	t.Run("undecodable body", func(t *testing.T) {
		assert.Equal(t, http.StatusBadRequest, serve(t, &stubLedger{}, http.MethodPost, paths.RedeemPath, `{`).Code)
	})

	t.Run("unknown fields", func(t *testing.T) {
		assert.Equal(t, http.StatusBadRequest, serve(t, &stubLedger{}, http.MethodPost, paths.RedeemPath, `{"x":1}`).Code)
	})

	t.Run("oversized body", func(t *testing.T) {
		body := `{"nonce":"` + strings.Repeat("a", maxLedgerRequestBytes) + `"}`
		assert.Equal(t, http.StatusBadRequest, serve(t, &stubLedger{}, http.MethodPost, paths.RedeemPath, body).Code)
	})

	t.Run("only POST is accepted", func(t *testing.T) {
		assert.Equal(t, http.StatusMethodNotAllowed, serve(t, &stubLedger{}, http.MethodGet, paths.RedeemPath, "").Code)
	})

	t.Run("unknown path", func(t *testing.T) {
		assert.Equal(t, http.StatusNotFound, serve(t, &stubLedger{}, http.MethodPost, "/v1/other", "{}").Code)
	})
}
