package oauthmngr

import (
	"errors"
	"fmt"

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
	// AllowInsecureCookieNames permits the session cookie name to omit the __Host- prefix.
	// It must only be set in development, where the stack runs on plain HTTP and a __Host-
	// cookie (which requires Secure) cannot be issued. In production the prefix prevents
	// sibling hosts from shadowing or injecting the session cookie (cookie tossing).
	AllowInsecureCookieNames bool
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

	if !c.AllowInsecureCookieNames && !oauthapi.HostScopedCookieName(c.SessionCookieName) {
		return fmt.Errorf("session cookie name %q must keep the %s prefix to resist cookie tossing from "+
			"sibling hosts; set --development to relax this for plain-HTTP testing",
			c.SessionCookieName, oauthapi.HostPrefix)
	}

	return nil
}

func validCookieName(name string) bool {
	_, err := cookies.NewRequest(name, "")

	return err == nil
}
