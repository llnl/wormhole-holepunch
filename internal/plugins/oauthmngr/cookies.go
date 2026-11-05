package oauthmngr

import (
	"errors"
	"strconv"
	"strings"
)

// cookieHeader creates a host-only, HttpOnly, SameSite=Lax cookie without net/http.
// Negative maxAge expires the cookie, and Secure is omitted only for plain HTTP.
func cookieHeader(name, value, path string, maxAge int, scheme string) (string, error) {
	if !validCookieName(name) || (value != "" && !validCookieValue(value)) {
		return "", errors.New("invalid cookie name or value")
	}

	if path == "" {
		path = "/"
	}

	if !strings.HasPrefix(path, "/") {
		return "", errors.New("cookie path must be absolute")
	}

	for i := range len(path) {
		if c := path[i]; c < ' ' || c >= 0x7f || c == ';' {
			return "", errors.New("invalid cookie path")
		}
	}

	var b strings.Builder
	b.WriteString(name)
	b.WriteByte('=')

	b.WriteString(value)

	b.WriteString("; Path=")
	b.WriteString(path)

	if maxAge > 0 {
		b.WriteString("; Max-Age=")
		b.WriteString(strconv.Itoa(maxAge))
	} else if maxAge < 0 {
		b.WriteString("; Max-Age=0")
	}

	b.WriteString("; HttpOnly")

	if scheme != "http" {
		b.WriteString("; Secure")
	}

	b.WriteString("; SameSite=Lax")

	return b.String(), nil
}
