package registry

import (
	"context"
	"time"

	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
	"github.com/llnl/wormhole-holepunch/internal/wormhole"
)

var (
	maxRetry  = 10
	waitRetry = 30 * time.Second
)

func (i *internal) request(ctx context.Context) ([]wormhole.RawSource, error) {
	var reqErr *requests.RequestFailedError

	resp := make([]wormhole.RawSource, 0)

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

func (i *internal) convert(raw wormhole.RawSource) authControls {
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
		preOauth:    i.oauthValid.EstablishPreAuthentication(raw),
		postOauth:   i.oauthValid.EstablishPostAuthentication(raw),
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
