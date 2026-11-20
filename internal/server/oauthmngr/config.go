package oauthmngr

import (
	"errors"

	"github.com/llnl/wormhole-holepunch/internal/ctls/cookies"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr/oauthapi"
)

// CallbackConfig configures the callback at paths.CallbackPrefix.
type CallbackConfig struct {
	// AuthDomain is the host where the session is captured.
	AuthDomain string
	// ProxyCookieName is the oauth2-proxy session cookie name.
	ProxyCookieName string
	// ProxySessionStore must match oauth2-proxy's session_store_type; it controls cookie chunking.
	ProxySessionStore oauthapi.SessionStore
	// SessionCookieName is the host-only session cookie name issued on the target host.
	SessionCookieName string
	// SessionCookieMaxAge is the session cookie lifetime in seconds.
	SessionCookieMaxAge int
}

func (c CallbackConfig) validate() error {
	switch {
	case oauthapi.HTTPSOrigin(c.AuthDomain) == "":
		return errors.New("a valid auth HTTPS authority is required by the callback")
	case !validCookieName(c.ProxyCookieName):
		return errors.New("proxy cookie name must be a valid cookie name")
	case !validCookieName(c.SessionCookieName):
		return errors.New("session cookie name must be a valid cookie name")
	case c.SessionCookieMaxAge <= 0:
		return errors.New("session cookie max age must be positive")
	case !c.ProxySessionStore.Valid():
		return errors.New("proxy session store is not supported")
	}

	return nil
}

func validCookieName(name string) bool {
	_, err := cookies.NewRequest(name, "")

	return err == nil
}
