// Package cookies creates validated HTTP cookies for native services.
package cookies

import (
	"errors"
	"net/http"
	"strings"
)

// Options controls a host-only response cookie's path, lifetime, and request scheme.
type Options struct {
	Path string
	// MaxAge follows net/http semantics: positive values are seconds, zero is
	// session-only, and negative values expire.
	MaxAge int
	Scheme string
}

// NewResponse creates a native host-only, HttpOnly, SameSite=Lax cookie using the shared response policy.
// Invalid attributes are rejected, the path defaults to "/", and Secure is omitted only for plain HTTP.
func NewResponse(name, value string, opts Options) (*http.Cookie, error) {
	if opts.Path == "" {
		opts.Path = "/"
	}

	if !strings.HasPrefix(opts.Path, "/") {
		return nil, errors.New("cookie path must be absolute")
	}

	cookie := &http.Cookie{ //nolint:gosec // Plain HTTP development endpoints cannot use Secure cookies.
		Name:     name,
		Value:    value,
		Path:     opts.Path,
		MaxAge:   opts.MaxAge,
		HttpOnly: true,
		Secure:   opts.Scheme != "http",
		SameSite: http.SameSiteLaxMode,
	}
	if err := cookie.Valid(); err != nil {
		return nil, err
	}

	return cookie, nil
}

// NewRequest creates a validated native name/value cookie for an outgoing HTTP request.
// It has no response-only attributes and does not issue a cookie to a browser.
func NewRequest(name, value string) (*http.Cookie, error) {
	//nolint:gosec // Request cookie, not a browser Set-Cookie.
	cookie := &http.Cookie{
		Name:  name,
		Value: value,
	}
	if err := cookie.Valid(); err != nil {
		return nil, err
	}

	return cookie, nil
}
