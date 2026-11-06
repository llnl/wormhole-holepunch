package oauthapi

import (
	"errors"
	"strconv"
	"strings"
)

// SessionStore mirrors oauth2-proxy's session_store_type, and must be configured to match.
type SessionStore string

const (
	// SessionStoreCookie stores the entire session in the cookie. Sessions too large for a
	// single cookie are split into numbered chunks (name_0, name_1, ...), so chunked cookies
	// are read from oauth2-proxy and issued on the sub-domain.
	SessionStoreCookie SessionStore = "cookie"
	// SessionStoreRedis stores the session server-side, leaving a small ticket in a single
	// cookie. Chunked cookies are never expected and are rejected.
	SessionStoreRedis SessionStore = "redis"

	// CookieChunkSize is the largest value placed in a single cookie, leaving headroom
	// beneath the 4096 byte browser limit for the name and attributes.
	CookieChunkSize = 3800
	// MaxCookieChunks bounds how many chunks are read or issued for a single session,
	// keeping the Cookie header within Envoy's default request header limits.
	MaxCookieChunks = 10
)

var (
	// ErrCookieNotFound indicates neither the cookie nor any of its chunks were present.
	ErrCookieNotFound = errors.New("cookie not found")
	// ErrCookieChunked indicates chunks were found where the session store forbids them,
	// typically oauth2-proxy and Holepunch disagreeing on the session store.
	ErrCookieChunked = errors.New("chunked cookie not permitted by session store")
	// ErrCookieTooLarge indicates the session exceeds what the session store can carry.
	ErrCookieTooLarge = errors.New("cookie exceeds session store limits")
)

// Valid reports whether s is a supported session store.
func (s SessionStore) Valid() bool {
	return s == SessionStoreCookie || s == SessionStoreRedis
}

// BindingCookieName returns the host-only cookie name for a single OAuth flow.
func BindingCookieName(nonce string) string {
	return BindingCookiePrefix + nonce
}

// ParseCookies parses one or more Cookie header values into name/value pairs. Where a name
// is repeated the first occurrence is retained, consistent with net/http's Request.Cookie.
func ParseCookies(headers ...string) map[string]string {
	cookies := make(map[string]string)

	for _, header := range headers {
		for pair := range strings.SplitSeq(header, ";") {
			name, value, ok := strings.Cut(strings.TrimSpace(pair), "=")
			if !ok || name == "" {
				continue
			}

			if _, seen := cookies[name]; !seen {
				cookies[name] = value
			}
		}
	}

	return cookies
}

// ChunkName returns the name of the i-th chunk of the cookie.
func ChunkName(name string, i int) string {
	return name + "_" + strconv.Itoa(i)
}

// IsCookieOrChunk reports whether candidate is the cookie itself or one of its chunks.
func IsCookieOrChunk(name, candidate string) bool {
	if candidate == name {
		return true
	}

	suffix, ok := strings.CutPrefix(candidate, name+"_")
	if !ok || suffix == "" {
		return false
	}

	for _, c := range []byte(suffix) {
		if c < '0' || c > '9' {
			return false
		}
	}

	return true
}

// JoinCookie reads the named cookie from the parsed cookies. Following oauth2-proxy, an
// unsplit cookie takes precedence; otherwise, for SessionStoreCookie, consecutive chunks
// starting at name_0 are concatenated.
func JoinCookie(cookies map[string]string, name string, store SessionStore) (string, error) {
	if v, ok := cookies[name]; ok && v != "" {
		return v, nil
	}

	first, chunked := cookies[ChunkName(name, 0)]

	switch {
	case !chunked:
		return "", ErrCookieNotFound
	case store != SessionStoreCookie:
		return "", ErrCookieChunked
	case first == "":
		return "", ErrCookieNotFound
	}

	var b strings.Builder

	for i := range MaxCookieChunks {
		v, ok := cookies[ChunkName(name, i)]
		if !ok {
			break
		}

		b.WriteString(v)
	}

	if _, ok := cookies[ChunkName(name, MaxCookieChunks)]; ok {
		return "", ErrCookieTooLarge
	}

	return b.String(), nil
}

// SplitCookie divides value into the name/value pairs to be issued for the session store:
// a single unsplit cookie whenever it fits, otherwise (SessionStoreCookie only) chunks of at
// most CookieChunkSize.
func SplitCookie(name, value string, store SessionStore) ([][2]string, error) {
	if len(value) <= CookieChunkSize {
		return [][2]string{{name, value}}, nil
	}

	if store != SessionStoreCookie {
		return nil, ErrCookieTooLarge
	}

	count := (len(value) + CookieChunkSize - 1) / CookieChunkSize
	if count > MaxCookieChunks {
		return nil, ErrCookieTooLarge
	}

	chunks := make([][2]string, 0, count)

	for i := range count {
		end := min((i+1)*CookieChunkSize, len(value))
		chunks = append(chunks, [2]string{ChunkName(name, i), value[i*CookieChunkSize : end]})
	}

	return chunks, nil
}

// RemoveCookie returns the Cookie header with the named cookie and all of its chunks
// removed, leaving the remaining "name=value" pairs intact.
func RemoveCookie(cookieHeader, name string) string {
	if cookieHeader == "" {
		return ""
	}

	kept := make([]string, 0)

	for pair := range strings.SplitSeq(cookieHeader, ";") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		if n, _, _ := strings.Cut(pair, "="); IsCookieOrChunk(name, n) {
			continue
		}

		kept = append(kept, pair)
	}

	return strings.Join(kept, "; ")
}
