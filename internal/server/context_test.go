package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/stretchr/testify/assert"
)

func initializeRequestWithLogger(
	t *testing.T,
	method, path string,
	body io.Reader,
) *http.Request {
	t.Helper()

	req := httptest.NewRequest(method, "http://example.com/"+path, body)
	ll := logs.InitializeDiscard()

	return setLogger(req, ll)
}

//

func Test_mustGetLogger(t *testing.T) {
	t.Run("set and get", func(t *testing.T) {
		req := initializeRequestWithLogger(t, http.MethodGet, "", nil)

		got := mustGetLogger(req.Context())

		assert.NotNil(t, got)
	})
}
