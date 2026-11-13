package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/paths"
	"github.com/llnl/wormhole-holepunch/internal/ctls/rules"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr"
	"github.com/llnl/wormhole-holepunch/internal/wormhole/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_data_ctlsReportHandler_routeKinds(t *testing.T) {
	staticFile := filepath.Join(t.TempDir(), "static.yaml")
	require.NoError(t, os.WriteFile(staticFile, []byte(`sources:
  - id: "4ff69450-30eb-489b-bb90-15f25cd88c7d"
    src: "https://foo.example.com/app"
    dst: "http://foo-svc:8080"
`), 0o600))

	for _, strategy := range []string{
		oauthmngr.StrategyNone, oauthmngr.StrategyOauth2ProxyReverse, oauthmngr.StrategyOauth2ProxyMiddleware,
	} {
		t.Run(strategy, func(t *testing.T) {
			ll := logs.InitializeDiscard()
			validator, err := oauthmngr.Initialize(nil, nil, ll, args.OauthManagement{
				Strategy: strategy, InternalProxyURL: "http://oauth2-proxy:4180",
				UserAuthURL: "auth.example.com", NonceTTL: 300, OauthLedgerURL: "http://oauthmngr:8083",
			})
			require.NoError(t, err)

			reg, err := registry.Initialize(context.Background(), nil, nil,
				args.RouteRegistry{RegistryHost: "http://registry", StaticCfg: staticFile}, ll,
				registry.WithSourceExpander(validator.ExpandSources),
			)
			require.NoError(t, err)
			d := &data{routeReg: reg}
			rec := httptest.NewRecorder()
			d.adminHandlers().ServeHTTP(rec,
				setLogger(httptest.NewRequest(http.MethodGet, paths.ControlsPath, nil), ll))

			require.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
			var report map[string]map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &report))
			require.Len(t, report, len(reg.FetchProxyControls()))
			kinds := make(map[string]int)
			for id, ctl := range reg.FetchProxyControls() {
				entry := report[id]
				require.NotNil(t, entry, id)
				var kind string
				require.NoError(t, json.Unmarshal(entry["kind"], &kind))
				assert.Equal(t, ctl.Kind.String(), kind, id)
				kinds[kind]++
				for _, field := range []string{"source", "destination", "id", "community_id", "allowed", "disallowed"} {
					assert.Contains(t, entry, field, "existing fields must be retained")
				}
			}
			expected := map[string]int{"upstream": 1}
			switch strategy {
			case oauthmngr.StrategyOauth2ProxyReverse:
				expected["oauth2-proxy"] = 1
			case oauthmngr.StrategyOauth2ProxyMiddleware:
				expected["oauth2-proxy"] = 1
				expected["oauth-callback"] = 2
			}
			assert.Equal(t, expected, kinds)
		})
	}
}

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
		req := initializeRequestWithLogger(t, http.MethodGet, paths.HealthPath, nil)

		rr := httptest.NewRecorder()
		healthzHandler(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Contains(t, rr.Body.String(), "ok")
	})
}

func Test_versionHandler(t *testing.T) {
	t.Run("get request", func(t *testing.T) {
		req := initializeRequestWithLogger(t, http.MethodGet, paths.VersionPath, nil)

		rr := httptest.NewRecorder()
		versionHandler(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Contains(t, rr.Body.String(), "version")
	})

	t.Run("get request", func(t *testing.T) {
		req := initializeRequestWithLogger(t, http.MethodDelete, paths.VersionPath, nil)

		rr := httptest.NewRecorder()
		versionHandler(rr, req)

		assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
	})
}
