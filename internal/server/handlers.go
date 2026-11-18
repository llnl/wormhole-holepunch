package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/paths"
	"github.com/llnl/wormhole-holepunch/internal/version"
)

// HandleCommon registers the health, version, and catch-all 404 handlers served by every
// Holepunch HTTP service. Register service routes first; "/" matches everything else.
func HandleCommon(mux *http.ServeMux) {
	mux.HandleFunc(paths.VersionPath, VersionHandler)
	mux.HandleFunc(paths.HealthPath, HealthzHandler)
	mux.HandleFunc("/", Generic404Handler)
}

/*
	general handlers
*/

// HealthzHandler reports liveness with the current UTC timestamp.
func HealthzHandler(w http.ResponseWriter, r *http.Request) {
	JSONContentHeader(w)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(fmt.Appendf(nil, `{"ok":true,"ts":"%s"}`+"\n", time.Now().UTC().Format(time.RFC3339Nano)))
}

// VersionHandler reports the running Holepunch version.
func VersionHandler(w http.ResponseWriter, r *http.Request) {
	ll := logs.MustFromContext(r.Context())

	ctx, end := ll.StartSpan(r.Context(), "versionHandler")
	defer end()

	if MethodNotAllowed(ctx, http.MethodGet, ll, w, r) {
		return
	}

	JSONContentHeader(w)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(fmt.Appendf(nil, "{\"version\": \"%s\"}\n", version.GetVersion()))
}

// Generic404Handler responds 404 for unmatched routes.
func Generic404Handler(w http.ResponseWriter, r *http.Request) {
	ll := logs.MustFromContext(r.Context())

	_, end := ll.StartSpan(r.Context(), "generic404Handler")
	defer end()

	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write(fmt.Append(nil, "404 Not Found"))
}

//

// JSONContentHeader sets a JSON Content-Type on the response.
func JSONContentHeader(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
}

// MethodNotAllowed writes a 405 and returns true when r.Method is not allowedMethod.
func MethodNotAllowed(
	ctx context.Context,
	allowedMethod string,
	ll logs.Logger,
	w http.ResponseWriter,
	r *http.Request,
) bool {
	if r.Method == allowedMethod {
		return false
	}

	ll.WarnCtx(ctx, r.Method+" method not allowed")

	w.WriteHeader(http.StatusMethodNotAllowed)
	_, _ = w.Write([]byte(http.StatusText(http.StatusMethodNotAllowed)))

	return true
}
