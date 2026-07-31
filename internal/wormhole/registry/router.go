package registry

import (
	"context"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/llnl/wormhole-holepunch/internal/ctls/errs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
	"github.com/llnl/wormhole-holepunch/internal/wormhole"
)

// ProxyControls offers a curated view of the registry response for the purposes of
// generating a web proxy to correct direct inbound traffic. These should be mapped
// to the unique ID (UUID) supplied by the route registry.
type ProxyControls struct {
	// Source offer the source URL to be used in identifying the request.
	Source keys.URLString
	// Destination offers the destination URL for the request.
	Destination keys.URLString
	// RequestHeaders is a key/value list of headers that should be set in
	// the associated request.
	RequestHeaders map[string]string
	// PrefixRewrite indicates that the matched prefix should (from the source)
	// will be swapped for this value.
	PrefixRewrite string
	// CommunityID is the unique identifier for the community associated with the route.
	CommunityID string
}

type Router interface {
	// AsyncFetchSources retrieves the latest route details, updating the cache and internal
	// controls. Any error encountered it logged to the system.
	AsyncFetchSources()

	// AuthorizeProxy examines details from an inbound request in order to determine if the
	// previously identified user is allowed to access the upstream resource.
	AuthorizeProxy(
		ctx context.Context,
		ll logs.Logger,
		req requests.RequestDetails,
		up wormhole.TokenContext,
	) *errs.StatusError

	// FetchProxyControls retrieves all currently known proxy controls.
	FetchProxyControls() map[string]ProxyControls

	// PublishSources retrieves that latest routes and publishes them if changes detected.
	PublishSources(ctx context.Context) error

	// RefreshControls safely updates the underlying internal structures used to manage
	// the known routes and how they are enforced.
	RefreshControls(msg jetstream.Msg)

	// ReportControlsJSON generate JSON output for those currently identified.
	ReportControlsJSON() []byte

	// SubscribeToSources
	SubscribeToSources(ctx context.Context) error
}
