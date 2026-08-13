package requests

import (
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
)

// RequestDetails is a generalized mapping for either more direct http
// requests or those associated with auth workflows. This structure should
// be used to avoid expanding the need for implementation specific request
// translations. All values should be derived from the proxy supplied
// details. Note that we do not validate the potential user defined values.
type RequestDetails struct {
	// Headers maps a subset of user defined key/value header that have been supplied
	// to the auth service, any header should be validated by the service prior to use.
	Headers map[string]string
	// RouteID is the identifier of the matched route. This should be derived from a
	// trusted value, for example the managed ext_authz context_extensions.
	RouteID string
	// CommunityID is the unique identifier for the community associated with the route.
	CommunityID string
	// Host for the inbound request used for routing/auth decisions. This should be
	// derived from a trusted value, for example the managed x-wormhole-host header.
	Host string
	// Scheme for the inbound request used for routing/auth decisions. This should be
	// derived from a trusted value, for example the managed x-wormhole-scheme header.
	Scheme string
	// Path use specified in request, rely on Envoy/proxy cleanup rules, by default no
	// additional validation preformed.
	Path string
	// ClientIP is the requesting client's address as identified by IdentifyClientIP from
	// the supplied Headers. Like Headers, this is user-influenceable input: it is only
	// guaranteed to look like an IPv4/IPv6 address, not that it is accurate.
	ClientIP string
}

//

// IdentifyClientIP extracts a client IP address from the headers, and validates that
// the result is a syntactically well-formed IPv4 or IPv6 address. It makes no claim
// about whether the address is accurate.
func IdentifyClientIP(headers map[string]string) string {
	ip := headers[keys.XForwardedForHeader]
	if ip == "" {
		ip = headers[keys.XRealIPHeader]
	}

	if ip == "" {
		return ""
	}

	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}

	if net.ParseIP(ip) == nil {
		return ""
	}

	return ip
}

func IdentifyURL(req *http.Request) string {
	var fullURL string

	if req.TLS != nil {
		fullURL = "https://" + req.Host
	} else {
		fullURL = "http://" + req.Host
	}

	if req.URL.Path == "" {
		return fullURL + req.Header.Get("X-Forwarded-Prefix")
	}

	return fullURL + req.URL.Path
}

func IdentifyPort(u *url.URL) uint32 {
	if port := u.Port(); port != "" {
		if parsedPort, err := strconv.Atoi(port); err == nil {
			return uint32(parsedPort) //nolint: gosec
		}
	}

	switch u.Scheme {
	case "https":
		return 443
	case "http":
		return 80
	default:
		return 0 // Return 0 for unknown schemes
	}
}

func IsLocalhost(u *url.URL) bool {
	hostname := u.Hostname()

	return hostname == "localhost" || hostname == "127.0.0.1" || strings.HasPrefix(hostname, "127.")
}

// HeaderToStringMap converts an http.Header into a map[string]string.
// Headers with no values, or only empty/whitespace values, are ignored.
// If a header has multiple values, the first non-empty one is used. All
// keys are set to lower case.
func HeaderToStringMap(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, vals := range h {
		for _, v := range vals {
			if v == "" {
				continue
			}

			out[strings.ToLower(k)] = v

			break
		}
	}

	if len(out) == 0 {
		return map[string]string{}
	}

	return out
}

// NormalizePath extracts the clean path prefix from the provided URL. If the URL
// path is empty, it defaults to "/".
func NormalizePath(src *url.URL) string {
	if src.Path == "" {
		return "/"
	}

	// Normalize the path to prevent traversal
	normalized := path.Clean(src.Path)

	// Ensure it starts with /
	if !strings.HasPrefix(normalized, "/") {
		normalized = "/" + normalized
	}

	return normalized
}
