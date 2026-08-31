// Package registry maintain a stable interface to the Route Registry service. This
// aims to enable dynamic creation/management for all required proxy configuration, in
// addition to the enforce authorization rules as specified by the list of managed routes.
// The know (stable) state provided by the registry is kept in memory in order to
// support the fastest lookups possible.
package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/ctls/errs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
	"github.com/llnl/wormhole-holepunch/internal/ctls/rules"
	"github.com/llnl/wormhole-holepunch/internal/ctls/streams"
	"github.com/llnl/wormhole-holepunch/internal/wormhole"
)

const (
	asyncTimeout   = 30 * time.Second
	ruleErrDetails = "request rejected based upon router rules"
)

func Initialize(
	ctx context.Context,
	client requests.Client,
	routePS streams.PubSub,
	routeRegArgs args.RouteRegistry,
	ll logs.Logger,
) (Router, error) {
	u, err := url.Parse(routeRegArgs.RegistryHost)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL %s: %w", routeRegArgs.RegistryHost, err)
	}

	staticSrc, err := loadStaticFile(ll, routeRegArgs.StaticCfg)
	if err != nil {
		return nil, fmt.Errorf("unable to open/parse %s: %w", routeRegArgs.StaticCfg, err)
	}

	adminRedirectAllow, err := normalizeHostMap(routeRegArgs.RedirectAllowList)
	if err != nil {
		return nil, fmt.Errorf("invalid redirect allowlist entry: %w", err)
	}

	i := &internal{
		adminRedirectAllow: adminRedirectAllow,
		client:             client,
		ll:                 ll,
		routePS:            routePS,
		routeRegArgs:       routeRegArgs,
		routesURL:          u.JoinPath(routeRegArgs.RoutePath).String(),
		staticSrc:          staticSrc,
		vv:                 rules.NewValidator(),

		authCtls:      make(map[string]authControls),
		proxyCtls:     make(map[string]ProxyControls),
		redirectAllow: make(map[string]struct{}),
	}

	// We will dynamically fetch/update the controls during the Holepunch
	// startup process, simply use this as an initial step to establish any
	// statically configured resources.
	i.updateCtls([]RawSource{})

	i.ll.Debug("successfully initialized routes")

	return i, nil
}

//

type internal struct {
	adminRedirectAllow map[string]struct{}
	client             requests.Client
	ll                 logs.Logger
	routePS            streams.PubSub
	routeRegArgs       args.RouteRegistry
	routesURL          string
	staticSrc          []RawSource
	vv                 rules.Validator

	mu sync.RWMutex
	// authControls offers the primary internal mechanism by which we realize the
	// Route Registries authorization and any policy enforcement. It offers a mapping
	// between ID and associated authorization details.
	authCtls map[string]authControls
	// proxyCtls provides an easy mapping between ID established
	// by the router services to the established src/dst, along with any
	// other required proxy configuration. It is designed to help establish
	// filters/routes through supported mechanisms.
	proxyCtls map[string]ProxyControls
	// redirectAllow is the set of hosts trusted as redirect targets. It is
	// rebuilt alongside authCtls/proxyCtls from the known routes' sources, and
	// seeded with any admin defined hosts from adminRedirectAllow.
	redirectAllow map[string]struct{}
}

// authControls is a managed structure of the router rules designed to
// encourage faster lookups and easy cache retrieval based upon the
// designated destination.
type authControls struct {
	Source      string      `json:"source"`
	Destination string      `json:"destination"`
	ID          string      `json:"id"`
	CommunityID string      `json:"community_id"`
	Allowed     userDetails `json:"allowed"`
	Disallowed  userDetails `json:"disallowed"`
}

type userDetails struct {
	Groups map[string]struct{} `json:"groups,omitempty"`
	Users  map[string]struct{} `json:"users,omitempty"`
}

//

func (i *internal) AsyncFetchSources() {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), asyncTimeout)
		defer cancel()

		err := i.PublishSources(ctx)
		if err != nil {
			i.ll.Error("AsyncFetchSources error: " + err.Error())
			return
		}

		i.ll.Info("AsyncFetchSources successfully fetched sources")
	}()
}

func (i *internal) AuthorizeProxy(
	ctx context.Context,
	ll logs.Logger,
	req requests.RequestDetails,
	tknCtx wormhole.TokenContext,
) *errs.StatusError {
	ctx, endSpan := ll.StartSpan(ctx, "AuthorizeProxy")
	defer endSpan()

	reqErr := i.authorizeProxyCtls(req, tknCtx)
	if reqErr != nil {
		ll.InfoCtx(
			ctx,
			tknCtx.Payload.Username+" denied access",
			ll.StringArg("tokenID", tknCtx.Payload.TokenID),
			ll.StringArg("error", reqErr.Error()),
		)

		return reqErr
	}

	ll.InfoCtx(
		ctx,
		tknCtx.Payload.Username+" access approved",
		ll.StringArg("tokenID", tknCtx.Payload.TokenID),
	)

	return nil
}

func (i *internal) FetchProxyControls() map[string]ProxyControls {
	i.mu.RLock()
	defer i.mu.RUnlock()

	return i.proxyCtls
}

func (i *internal) PublishSources(ctx context.Context) error {
	i.ll.Debug("fetching registry: " + i.routesURL)

	sources, err := i.request(ctx)
	if err != nil {
		return fmt.Errorf("request error: %w", err)
	}

	return i.routePS.PublishSingleMsg(ctx, &sources)
}

func (i *internal) RefreshControls(msg jetstream.Msg) {
	var sources []RawSource

	err := json.Unmarshal(msg.Data(), &sources)
	if err != nil {
		i.ll.Errorf("invalid message json: %s", err.Error())
		return
	}

	i.updateCtls(sources)
}

func (i *internal) ReportControlsJSON() []byte {
	i.mu.RLock()
	defer i.mu.RUnlock()

	b, _ := json.Marshal(i.authCtls)

	return b
}

func (i *internal) SubscribeToSources(ctx context.Context) error {
	return i.routePS.Consume(ctx, i.RefreshControls)
}

func (i *internal) AllowedRedirect(proposedURL string) bool {
	urlStr, err := keys.NormalizeURL(proposedURL)
	if err != nil || urlStr.Key == "" {
		return false
	}

	i.mu.RLock()
	defer i.mu.RUnlock()

	_, found := i.redirectAllow[urlStr.Key]

	return found
}

//

func (i *internal) authorizeProxyCtls(
	req requests.RequestDetails,
	tknCtx wormhole.TokenContext,
) *errs.StatusError {
	// Read controls and version atomically
	i.mu.RLock()

	id, gErr := i.identifyID(req)
	if gErr != nil {
		i.mu.RUnlock()
		return gErr
	}

	ctl, found := i.authCtls[id]

	i.mu.RUnlock()

	if !found {
		return errs.NewNotFoundErr(errors.New("no route found for " + id))
	}

	// The presence of any external_id in a token's payload implies it's a subtoken
	// and thus must be properly scoped to the matching community. Other tokens
	// do not require this step.
	if tknCtx.Payload.ExternalID != "" && ctl.CommunityID != tknCtx.Payload.ExternalID {
		errMsg := "subtoken does not align with required community: " + ctl.CommunityID
		return errs.NewAuthErr(errors.New(errMsg), errMsg)
	}

	// Perform authorization check WITHOUT holding lock
	// This is safe because authControls is immutable after creation
	reqErr := ctl.enforce(tknCtx)

	return reqErr
}

func (i *internal) identifyID(req requests.RequestDetails) (string, *errs.StatusError) {
	id := req.RouteID
	if err := i.vv.Var(id, "omitempty,uuid"); err != nil {
		return "", err
	}

	if id == "" {
		// This (or the prior validation) error shouldn't occur since we
		// control the headers before auth is requested. We want to make sure
		// theses are logged so we can act upon such bugs quickly.
		return "", errs.SimpleInternalErr(
			fmt.Errorf("no %s found in request", keys.PikoHeader),
		)
	}

	// Pre-check the controls to provide a clearer error message if the target
	// destination is not supported at time of check.
	_, found := i.authCtls[id]
	if !found {
		return "", errs.NewNotFoundErr(errors.New("no destination for " + id))
	}

	return id, nil
}

func (i *internal) updateCtls(sources []RawSource) {
	authCtls := make(map[string]authControls, 0)
	proxyCtls := make(map[string]ProxyControls, 0)

	// Seed the redirect allow list with any admin defined hosts; every known
	// route's source host is then added below, so a route is always a trusted
	// redirect target by default.
	redirectAllow := make(map[string]struct{}, len(i.adminRedirectAllow))
	for host := range i.adminRedirectAllow {
		redirectAllow[host] = struct{}{}
	}

	for _, rs := range append(i.staticSrc, sources...) {
		i.ll.Debugf("updating mapping for %s (%s)", rs.Destination.Raw, rs.ID)

		authCtls[rs.ID] = i.convert(rs)
		proxyCtls[rs.ID] = ProxyControls{
			Source:      rs.Source,
			Destination: rs.Destination,
			// Currently there are no additional headers that are required to be
			// set for the proxy driven by the route configuration.
			RequestHeaders: map[string]string{},
			CommunityID:    rs.CommunityID,
			PrefixRewrite:  rs.PrefixRewrite,
		}

		if rs.Source.Key != "" {
			redirectAllow[rs.Source.Key] = struct{}{}
		}
	}

	i.mu.Lock()
	i.authCtls = authCtls
	i.proxyCtls = proxyCtls
	i.redirectAllow = redirectAllow
	i.mu.Unlock()
}

//

// enforce checks the proposed token context (user + group) against the authorization
// rules established for the route, following the following priority:
//  1. Explicit user deny (highest priority)
//  2. Group deny
//  3. Explicit user allow
//  4. Group allow
//  5. Deny by default (lowest priority)
func (a authControls) enforce(tknCtx wormhole.TokenContext) *errs.StatusError {
	username := tknCtx.Payload.Username
	groups := tknCtx.Payload.Groups

	if _, found := a.Disallowed.Users[username]; found {
		return errs.NewAuthErr(
			errors.New("user explicitly denied"),
			ruleErrDetails,
		)
	}

	for _, group := range groups {
		if _, found := a.Disallowed.Groups[group]; found {
			return errs.NewAuthErr(
				errors.New("user group denied"),
				ruleErrDetails,
			)
		}
	}

	if _, found := a.Allowed.Users[username]; found {
		return nil
	}

	for _, group := range groups {
		if _, found := a.Allowed.Groups[group]; found {
			return nil
		}
	}

	return errs.NewAuthErr(
		errors.New("deny by default"),
		ruleErrDetails,
	)
}
