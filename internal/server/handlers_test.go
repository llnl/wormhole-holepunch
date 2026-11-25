package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/paths"
)

func initializeRequestWithLogger(
	t *testing.T,
	method, path string,
	body io.Reader,
) *http.Request {
	t.Helper()

	req := httptest.NewRequest(method, "http://example.com/"+path, body)

	return req.WithContext(logs.NewContext(req.Context(), logs.InitializeDiscard()))
}

//

func Test_HandleCommon(t *testing.T) {
	mux := http.NewServeMux()
	HandleCommon(mux)

	for path, want := range map[string]int{
		paths.HealthPath:  http.StatusOK,
		paths.VersionPath: http.StatusOK,
		"/unknown":        http.StatusNotFound,
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req.WithContext(logs.NewContext(req.Context(), logs.InitializeDiscard())))

		assert.Equal(t, want, rr.Code, path)
	}
}

func Test_Generic404Handler(t *testing.T) {
	t.Run("get request", func(t *testing.T) {
		req := initializeRequestWithLogger(t, http.MethodGet, "", nil)

		rr := httptest.NewRecorder()
		Generic404Handler(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
		assert.Equal(t, "404 Not Found", rr.Body.String())
	})
}

func Test_HealthzHandler(t *testing.T) {
	t.Run("get request", func(t *testing.T) {
		req := initializeRequestWithLogger(t, http.MethodGet, paths.HealthPath, nil)

		rr := httptest.NewRecorder()
		HealthzHandler(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Contains(t, rr.Body.String(), "ok")
	})
}

func Test_VersionHandler(t *testing.T) {
	t.Run("get request", func(t *testing.T) {
		req := initializeRequestWithLogger(t, http.MethodGet, paths.VersionPath, nil)

		rr := httptest.NewRecorder()
		VersionHandler(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Contains(t, rr.Body.String(), "version")
	})

	t.Run("get request", func(t *testing.T) {
		req := initializeRequestWithLogger(t, http.MethodDelete, paths.VersionPath, nil)

		rr := httptest.NewRecorder()
		VersionHandler(rr, req)

		assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
	})
}
