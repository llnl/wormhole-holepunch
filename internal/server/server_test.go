package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
)

func TestWaitForShutdownDrainsActiveRequest(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	finishRequest := sync.OnceFunc(func() { close(release) })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	defer finishRequest()

	requestCtx, cancelRequest := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelRequest()

	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, srv.URL, nil)
	require.NoError(t, err)

	type result struct {
		status int
		err    error
	}

	requestDone := make(chan result, 1)

	go func() {
		resp, err := srv.Client().Do(req)
		if err != nil {
			requestDone <- result{err: err}

			return
		}

		requestDone <- result{status: resp.StatusCode, err: resp.Body.Close()}
	}()

	select {
	case <-started:
	case res := <-requestDone:
		t.Fatalf("request exited before reaching handler: %+v", res)
	case <-requestCtx.Done():
		t.Fatal("request did not reach handler")
	}

	shutdownStarted := make(chan struct{})
	srv.Config.RegisterOnShutdown(func() { close(shutdownStarted) })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	shutdownDone := make(chan error, 1)

	go func() {
		shutdownDone <- waitForShutdown(ctx, logs.InitializeDiscard(), srv.Config, nil)
	}()

	select {
	case <-shutdownStarted:
	case <-requestCtx.Done():
		t.Fatal("server did not start shutdown")
	}

	select {
	case err := <-shutdownDone:
		t.Fatalf("shutdown returned before the active request completed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	finishRequest()
	res := <-requestDone
	require.NoError(t, res.err)
	require.Equal(t, http.StatusNoContent, res.status)

	select {
	case err := <-shutdownDone:
		require.NoError(t, err)
	case <-requestCtx.Done():
		t.Fatal("shutdown did not finish after the active request completed")
	}
}
