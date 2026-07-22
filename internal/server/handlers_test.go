package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/llnl/wormhole-holepunch/internal/ctls/rules"
	"github.com/stretchr/testify/assert"
)

func Test_data_adminHandlers(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		d := &data{}
		got := d.adminHandlers()

		// We don't have any login in building the handlers in this way.
		assert.NotNil(t, got)
	})
}

func Test_data_invalidateWebhookHandler(t *testing.T) {
	vv := rules.NewValidator()

	tests := map[string]struct {
		name       string
		method     string
		body       string
		wantStatus int
	}{
		"invalid json": {
			method:     http.MethodPost,
			body:       `{"token_id":`, // truncated
			wantStatus: http.StatusBadRequest,
		},
		"unknown field rejected": {
			method:     http.MethodPost,
			body:       `{"token_id":"550e8400-e29b-41d4-a716-446655440000","nope":true}`,
			wantStatus: http.StatusBadRequest,
		},
		"token_id not a uuid": {
			method:     http.MethodPost,
			body:       `{"token_id":"not-a-uuid","subtokens":[]}`,
			wantStatus: http.StatusBadRequest,
		},
		"subtoken id not a uuid": {
			method:     http.MethodPost,
			body:       `{"token_id":"550e8400-e29b-41d4-a716-446655440000","subtokens":[{"id":"bad","external_id":"550e8400-e29b-41d4-a716-446655440000"}]}`,
			wantStatus: http.StatusBadRequest,
		},
		"external_id not a uuid": {
			method:     http.MethodPost,
			body:       `{"token_id":"550e8400-e29b-41d4-a716-446655440000","subtokens":[{"id":"550e8400-e29b-41d4-a716-446655440001","external_id":"bad"}]}`,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := &data{
				vv: vv,
			}

			req := initializeRequestWithLogger(t, tc.method, "/revoke", bytes.NewBufferString(tc.body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			d.invalidateWebhookHandler(rr, req)

			res := rr.Result()
			defer res.Body.Close()

			assert.Equal(t, tc.wantStatus, res.StatusCode)
		})
	}
}

func Test_generic404Handler(t *testing.T) {
	t.Run("get request", func(t *testing.T) {
		req := initializeRequestWithLogger(t, http.MethodGet, "", nil)

		rr := httptest.NewRecorder()
		generic404Handler(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
		assert.Equal(t, "404 Not Found", rr.Body.String())
	})
}

func Test_healthzHandler(t *testing.T) {
	t.Run("get request", func(t *testing.T) {
		req := initializeRequestWithLogger(t, http.MethodGet, defaultPrefix+"healthz", nil)

		rr := httptest.NewRecorder()
		healthzHandler(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Contains(t, rr.Body.String(), "ok")
	})
}

func Test_versionHandler(t *testing.T) {
	t.Run("get request", func(t *testing.T) {
		req := initializeRequestWithLogger(t, http.MethodGet, defaultPrefix+"version", nil)

		rr := httptest.NewRecorder()
		versionHandler(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Contains(t, rr.Body.String(), "version")
	})

	t.Run("get request", func(t *testing.T) {
		req := initializeRequestWithLogger(t, http.MethodDelete, defaultPrefix+"version", nil)

		rr := httptest.NewRecorder()
		versionHandler(rr, req)

		assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
	})
}
