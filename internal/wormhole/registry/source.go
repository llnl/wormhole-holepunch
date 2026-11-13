package registry

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/paths"
	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
)

var (
	maxRetry  = 10
	waitRetry = 30 * time.Second
)

type RawSource struct {
	ID          string         `json:"id" yaml:"id" validate:"uuid"`
	Source      keys.URLString `json:"src" yaml:"src" validate:"required,wormholeURL"`
	Destination keys.URLString `json:"dst" yaml:"dst" validate:"required,wormholeURL"`
	// PrefixRewrite defines how any URL path defined in the Source will be rewritten before
	// passing along to the Destination. At this time only the statically defined source file
	// offers the ability to provide this configuration.
	PrefixRewrite string `json:"prefix_rewrite" yaml:"prefix_rewrite"`
	CommunityID   string `json:"community_id" yaml:"community_id" validate:"omitempty,uuid"`
	Rules         struct {
		Disallowed struct {
			Users  []string `json:"users" yaml:"users" validate:"omitempty,headerVal"`
			Groups []string `json:"groups" yaml:"groups" validate:"omitempty,headerVal"`
		} `json:"disallowed" yaml:"disallowed"`
		Allowed struct {
			Users  []string `json:"users" yaml:"users" validate:"omitempty,headerVal"`
			Groups []string `json:"groups" yaml:"groups" validate:"omitempty,headerVal"`
		} `json:"allowed" yaml:"allowed"`
	} `json:"rules" yaml:"rules"`
	// NoAuth disables the ext_authz (holepunch-authz) filter for the route. This is an
	// internal control set by static-source configuration or trusted source expanders and
	// must never be decodable from the route registry (or any JSON).
	NoAuth bool `json:"-" yaml:"-"`
	// Kind identifies the purpose of the route, used by xDS to select the route action and
	// per-route filter configuration. Only oauthmngr's ExpandSources may establish anything
	// other than the default RouteKindUpstream, it must never be decodable from the route
	// registry (or any JSON).
	Kind RouteKind `json:"-" yaml:"-"`
}

// RouteKind categorizes a route by how Envoy must handle it. The zero value is
// RouteKindUpstream so any user supplied route is a traditional upstream route.
type RouteKind int

const (
	// RouteKindUpstream forwards to the destination cluster.
	RouteKindUpstream RouteKind = iota
	// RouteKindOauth2Proxy forwards to the oauth2-proxy cluster.
	RouteKindOauth2Proxy
	// RouteKindOauthCallback forwards to the oauthmngr ledger cluster, with the client
	// address and the route's host and scheme bound into the request.
	RouteKindOauthCallback
	// RouteKindReserved is a direct_response 404 reserving the /-/wormhole/ prefix on every
	// virtual host.
	RouteKindReserved
)

func (k RouteKind) String() string {
	switch k {
	case RouteKindUpstream:
		return "upstream"
	case RouteKindOauth2Proxy:
		return "oauth2-proxy"
	case RouteKindOauthCallback:
		return "oauth-callback"
	case RouteKindReserved:
		return "reserved"
	default:
		return fmt.Sprintf("unknown(%d)", int(k))
	}
}

//

func (i *internal) request(ctx context.Context) ([]RawSource, error) {
	var reqErr *requests.RequestFailedError

	resp := make([]RawSource, 0)

	for range maxRetry {
		reqErr = i.client.GetJSON(ctx, i.routesURL, map[string]string{}, &resp)
		if reqErr == nil {
			if err := i.vv.Var(resp, "dive"); err != nil {
				// Since we trust the route registry configuration and its vetting or
				// any user values, this is likely an indication of a miss-configuration or
				// a bug in Holepunch's understanding. Regardless of the case it is best to
				// fail the update the log the error.
				i.ll.ErrorCtx(
					ctx,
					"invalid registry source",
					i.ll.StringArg("error", err.Error()),
				)

				return resp, err
			}

			return resp, nil
		}

		time.Sleep(waitRetry)
	}

	return resp, reqErr
}

func (i *internal) convert(raw RawSource) authControls {
	return authControls{
		Allowed: userDetails{
			Groups: sliceToMap(raw.Rules.Allowed.Groups),
			Users:  sliceToMap(raw.Rules.Allowed.Users),
		},
		Disallowed: userDetails{
			Groups: sliceToMap(raw.Rules.Disallowed.Groups),
			Users:  sliceToMap(raw.Rules.Disallowed.Users),
		},
		ID:          raw.ID,
		Kind:        raw.Kind.String(),
		Destination: raw.Destination.Raw,
		Source:      raw.Source.Key,
		SourcePath:  requests.NormalizePath(raw.Source.URL),
		CommunityID: raw.CommunityID,
		NoAuth:      raw.NoAuth,
	}
}

//

// reservedSource reports whether the source's path falls within the /-/wormhole/ prefix
// Holepunch reserves for its own routes. The path is compared after the same cleaning used to
// establish the Envoy route prefix, so variations (e.g., "//", "..") cannot escape the check.
func reservedSource(rs RawSource) bool {
	if rs.Source.URL == nil {
		return false
	}

	p := requests.NormalizePath(rs.Source.URL)

	return p == strings.TrimSuffix(paths.ReservedPrefix, "/") || strings.HasPrefix(p, paths.ReservedPrefix)
}

// dropReserved removes any source within the reserved prefix. These are rejected
// individually so a single invalid route cannot prevent the remainder from updating.
func (i *internal) dropReserved(sources []RawSource) []RawSource {
	kept := make([]RawSource, 0, len(sources))

	for _, rs := range sources {
		if reservedSource(rs) {
			i.ll.Errorf("rejecting route %s: %s is within the reserved %s prefix",
				rs.ID, rs.Source.Raw, paths.ReservedPrefix)

			continue
		}

		kept = append(kept, rs)
	}

	return kept
}

func sliceToMap(s []string) map[string]struct{} {
	m := make(map[string]struct{}, len(s))
	for _, v := range s {
		m[v] = struct{}{}
	}

	return m
}

func normalizeHostMap(hosts []string) (map[string]struct{}, error) {
	m := make(map[string]struct{}, len(hosts))

	for _, h := range hosts {
		urlStr, err := keys.NormalizeURL(h)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", h, err)
		}

		m[urlStr.Key] = struct{}{}
	}

	return m, nil
}
