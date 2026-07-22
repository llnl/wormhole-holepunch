package registry

import (
	"context"
	"time"

	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
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
		Destination: raw.Destination.Raw,
		Source:      raw.Source.Key,
		CommunityID: raw.CommunityID,
	}
}

//

func sliceToMap(s []string) map[string]struct{} {
	m := make(map[string]struct{}, len(s))
	for _, v := range s {
		m[v] = struct{}{}
	}

	return m
}
