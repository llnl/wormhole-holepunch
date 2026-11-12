package oauthmngr

import (
	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
	"github.com/llnl/wormhole-holepunch/internal/wormhole/registry"
)

// virtualHost identifies a single Envoy virtual host for which routes are injected.
type virtualHost struct {
	scheme string
	host   string
}

// virtualHosts returns every unique hostname referenced by the sources, in the order first
// observed, retaining each host's configured scheme. Paths and ports do not distinguish
// Envoy virtual hosts.
func virtualHosts(rawSources []registry.RawSource) []virtualHost {
	seen := make(map[string]struct{})
	vhosts := make([]virtualHost, 0)

	for _, src := range rawSources {
		if src.Source.URL == nil || src.Source.URL.Hostname() == "" {
			continue
		}

		vh := virtualHost{
			scheme: defaultScheme(src.Source.URL.Scheme),
			host:   src.Source.URL.Hostname(),
		}

		if _, ok := seen[vh.host]; ok {
			continue
		}

		seen[vh.host] = struct{}{}
		vhosts = append(vhosts, vh)
	}

	return vhosts
}

// newRoute builds a route injected by ExpandSources for the virtual host. The ID is derived
// from the kind and virtual host so it remains stable across snapshots regardless of the
// order sources are supplied. Callback routes have no upstream destination.
func newRoute(vh virtualHost, prefix string, kind registry.RouteKind, destination string) registry.RawSource {
	route := registry.RawSource{
		ID:     "wormhole-" + kind.String() + "-" + vh.host,
		Source: urlString(vh.scheme + "://" + vh.host + prefix),
		Kind:   kind,
		NoAuth: true,
	}

	if destination != "" {
		route.Destination = urlString(destination)
	}

	return route
}

// urlString wraps keys.NormalizeURL for URLs constructed from already parsed components,
// where a parsing failure is not possible.
func urlString(raw string) keys.URLString {
	u, _ := keys.NormalizeURL(raw)

	return u
}

// defaultScheme returns https unless the scheme has been explicitly provided.
func defaultScheme(scheme string) string {
	if scheme == "" {
		return "https"
	}

	return scheme
}

// requestScheme returns the scheme of the request, defaulting to https.
func requestScheme(details requests.RequestDetails) string {
	return defaultScheme(details.Scheme)
}
