// Package plugins organizes Holepunch's proxy-wasm plugins, Envoy extensions built from this
// repository so they share types and test fixtures with the control plane that configures
// them. Each plugin follows the same layout:
//
//   - internal/plugins/<name>: the plugin implementation, exposing a Register function that
//     installs its proxy-wasm contexts. Tested natively (go test) through the SDK's proxytest
//     host emulator.
//   - cmd/plugins/<name>: the module entrypoint, calling Register from init. Built as a
//     GOOS=wasip1 reactor module (-buildmode=c-shared) into binaries/<name>.wasm by
//     make build-wasm.
//
// Plugins are compiled to WebAssembly, so they must only import packages that are free of
// heavy or wasm-incompatible dependencies (e.g., internal/oauthmngr/oauthapi rather than
// internal/oauthmngr). Envoy's wasm runtime only provides a subset of WASI, any package
// linking filesystem access (notably net) produces a module Envoy refuses to load. This is
// enforced by Test_wasmImports in each plugin.
//
// Plugins:
//
//   - oauthmngr: the cookie hand-off callback for the oauth2-proxy-middleware strategy
//     (see docs/oauth-manager.md).
package plugins
