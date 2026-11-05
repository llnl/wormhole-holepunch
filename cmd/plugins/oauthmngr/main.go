// Command oauthmngr is the oauthmngr proxy-wasm plugin module loaded by Envoy for the
// oauth2-proxy-middleware strategy. It must be built as a reactor module:
//
//	GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o oauthmngr.wasm ./cmd/plugins/oauthmngr
//
// or for every plugin: make build-wasm
package main

import (
	"github.com/llnl/wormhole-holepunch/internal/plugins/oauthmngr"
)

// The host invokes _initialize, which runs package initialization but never main.
func init() { //nolint:gochecknoinits // required entrypoint for proxy-wasm reactor modules
	oauthmngr.Register()
}

func main() {}
