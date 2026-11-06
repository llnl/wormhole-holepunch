// Package oauthmngr implements the oauthmngr proxy-wasm plugin, the Envoy-side half of the
// oauth2-proxy-middleware strategy (see docs/oauth-manager.md). It is enabled only on the
// generated oauth-callback routes and answers every request with a local reply:
//
//   - At the auth domain it captures the oauth2-proxy session cookie against the nonce via
//     the Ledger, then redirects to the target sub-domain callback.
//   - At the target sub-domain it redeems the nonce via the Ledger, then redirects to the
//     user's intended destination with a host-only sub-domain session cookie.
//
// The plugin never continues a request upstream. It is built with GOOS=wasip1 from
// cmd/plugins/oauthmngr, and tested natively through the SDK's proxytest host emulator.
package oauthmngr

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm"
	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm/types"

	"github.com/llnl/wormhole-holepunch/internal/oauthmngr/oauthapi"
)

// Register installs the plugin's VM context. It must be called from an init function of the
// wasm module's main package.
func Register() {
	proxywasm.SetVMContext(&vmContext{})
}

type vmContext struct {
	types.DefaultVMContext
}

func (*vmContext) NewPluginContext(uint32) types.PluginContext {
	return &pluginContext{}
}

// pluginContext holds the validated configuration shared by every HTTP stream.
type pluginContext struct {
	types.DefaultPluginContext

	cfg oauthapi.PluginConfig
}

// OnPluginStart parses and validates the configuration. Failing here prevents the plugin
// from loading which, with failure_policy FAIL_CLOSED, rejects traffic on the callback route.
func (p *pluginContext) OnPluginStart(int) types.OnPluginStartStatus {
	data, err := proxywasm.GetPluginConfiguration()
	if err != nil && !errors.Is(err, types.ErrorStatusNotFound) {
		proxywasm.LogCriticalf("oauthmngr: unable to read plugin configuration: %v", err)
		return types.OnPluginStartStatusFailed
	}

	cfg, err := parseConfig(data)
	if err != nil {
		proxywasm.LogCriticalf("oauthmngr: invalid plugin configuration: %v", err)
		return types.OnPluginStartStatusFailed
	}

	p.cfg = cfg

	return types.OnPluginStartStatusOK
}

func (p *pluginContext) NewHttpContext(uint32) types.HttpContext {
	return &httpContext{cfg: &p.cfg}
}

// parseConfig decodes the xDS supplied configuration, applying defaults and rejecting
// anything that would produce an unusable or unsafe cookie.
func parseConfig(data []byte) (oauthapi.PluginConfig, error) {
	var cfg oauthapi.PluginConfig

	if len(data) == 0 {
		return cfg, errors.New("configuration is empty")
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("decoding: %w", err)
	}

	if cfg.LedgerTimeoutMs == 0 {
		cfg.LedgerTimeoutMs = oauthapi.LedgerTimeoutMs
	}

	if cfg.ProxySessionStore == "" {
		cfg.ProxySessionStore = oauthapi.SessionStoreCookie
	}

	switch {
	case cfg.AuthDomain == "":
		return cfg, errors.New("auth_domain is required")
	case cfg.LedgerCluster == "":
		return cfg, errors.New("ledger_cluster is required")
	case !validCookieName(cfg.ProxyCookieName):
		return cfg, errors.New("proxy_cookie_name must be a valid cookie name")
	case !validCookieName(cfg.SessionCookieName):
		return cfg, errors.New("session_cookie_name must be a valid cookie name")
	case cfg.SessionCookieMaxAge <= 0:
		return cfg, errors.New("session_cookie_max_age must be positive")
	case !cfg.ProxySessionStore.Valid():
		return cfg, fmt.Errorf("proxy_session_store %q is not supported", cfg.ProxySessionStore)
	case cfg.LedgerTimeoutMs < 0:
		return cfg, errors.New("ledger_timeout_ms must not be negative")
	}

	return cfg, nil
}
