package token

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"github.com/llnl/wormhole-holepunch/internal/ctls/errs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
	"github.com/llnl/wormhole-holepunch/internal/wormhole"
)

type tokenReqBody struct {
	Name string `json:"name"`
}

type subtokenReqBody struct {
	Token      tokenReqBody `json:"token"`
	ParentID   string       `json:"parent_id"`
	ExternalID string       `json:"external_id"`
}

type subtokenResp struct {
	Token string `json:"token"`
}

type subtokenCache struct {
	ID         string             `json:"id"`
	Token      string             `json:"token"`
	ParentID   string             `json:"parent_id"`
	ExternalID string             `json:"external_id"`
	Exp        wormhole.FloatTime `json:"exp"`
}

//

func (i internal) SubtokenFlow(
	ctx context.Context,
	ll logs.Logger,
	req requests.RequestDetails,
	tknCtx wormhole.TokenContext,
) (string, *errs.StatusError) {
	ctx, endSpan := ll.StartSpan(ctx, "SubtokenFlow")
	defer endSpan()

	externalID := req.Headers[keys.CommunityHeader]
	if externalID == "" {
		// This request is not part of a community so any subtoken
		// creation will not be required.
		return "", nil
	}

	ll.InfoCtx(
		ctx,
		"community identified",
		ll.StringArg("externalID", externalID),
	)

	if tknCtx.Payload.ExternalID == externalID && tknCtx.Payload.ParentID != "" {
		// This implies that validated token is a subtoken, thus we never
		// want to generate a new subtoken. Instead we pass it back along.
		ll.DebugCtx(
			ctx,
			"identified existing subtoken",
			ll.StringArg("subtokenID", tknCtx.Payload.TokenID),
		)

		return tknCtx.WAT, nil
	}

	ll.InfoCtx(
		ctx,
		"creating subtoken",
		ll.StringArg("parentID", tknCtx.Payload.TokenID),
	)

	cs := subtokenCache{}
	key := keys.WormholeAccessSubtoken(tknCtx.Payload.TokenID, externalID)
	now := time.Now()

	err := i.kvStore.Get(ctx, key, &cs)
	if err == nil && cs.Token != "" {
		if now.Before(cs.Exp.Time) {
			ll.DebugCtx(ctx, "subtoken cache hit")

			return cs.Token, nil
		} else {
			// Token expiring in cache is possible since NATS does not
			// support per entry expiration. Ideally we deal with most
			// of these cases with the proper cache maintenance.
			_ = i.kvStore.Delete(ctx, key)

			ll.DebugCtx(
				ctx,
				"subtoken expired, attempting to request new",
				ll.StringArg("subtokenID", cs.ID),
			)
		}
	}

	return i.generateSubToken(ctx, ll, tknCtx, externalID, key)
}

//

func (i internal) generateSubToken(
	ctx context.Context,
	ll logs.Logger,
	tknCtx wormhole.TokenContext,
	communityID, key string,
) (string, *errs.StatusError) {
	subtoken, err := i.postSubtokenRequest(ctx, tknCtx, communityID)
	if err != nil {
		return "", errs.NewInternalErr(err, "failed to generate subtoken")
	}

	cs := subtokenCache{
		Token:      subtoken,
		ID:         tknCtx.Payload.TokenID,
		ParentID:   tknCtx.Payload.ParentID,
		ExternalID: communityID,
		// Expiration for the subtoken is tied to the parent.
		Exp: tknCtx.Payload.Exp,
	}

	err = i.kvStore.Put(ctx, key, cs)
	if err != nil {
		ll.WarnCtx(
			ctx,
			"unable to cache subtoken response",
			ll.StringArg("error", err.Error()),
		)
	}

	ll.Infof(
		"generated subtoken %s for community %s",
		tknCtx.Payload.TokenID,
		communityID,
	)

	return cs.Token, nil
}

// postSubtokenRequest constructs the POST request to the admin token endpoint, requesting a
// subtoken scoped to the given community and parent.
func (i internal) postSubtokenRequest(
	ctx context.Context,
	tknCtx wormhole.TokenContext,
	communityID string,
) (string, error) {
	b, _ := json.Marshal(buildSubtokenReq(tknCtx, communityID))
	resp := subtokenResp{}

	reqURL := i.subtokenReqURL + "/" + tknCtx.Payload.Username

	headers := make(map[string]string, 0)
	if i.tokenSvcArgs.TokenServiceAdmin != "" {
		headers[i.tokenSvcArgs.TokenHeader] = i.tokenSvcArgs.TokenServiceAdmin
	}

	err := i.client.PostJSONBody(ctx, reqURL, headers, bytes.NewReader(b), &resp)
	if err != nil {
		return "", err
	}

	return resp.Token, nil
}

//

func buildSubtokenReq(
	tknCtx wormhole.TokenContext,
	communityID string,
) subtokenReqBody {
	return subtokenReqBody{
		Token: tokenReqBody{
			Name: "subtoken",
		},
		ExternalID: communityID,
		ParentID:   tknCtx.Payload.TokenID,
	}
}
