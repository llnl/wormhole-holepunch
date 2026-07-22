package token

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/ctls/errs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
	"github.com/llnl/wormhole-holepunch/internal/ctls/streams"
	"github.com/llnl/wormhole-holepunch/internal/wormhole"
	"github.com/llnl/wormhole-holepunch/test/mocks/mock_requests"
	"github.com/llnl/wormhole-holepunch/test/mocks/mock_streams"
)

func Test_internal_SubtokenFlow(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	parentID := "c520c08c-0325-48c4-8bd1-57bde8c7c382"
	tokenFoo := parentID + ".foo"

	subID := "6f1dd5eb-d058-433f-89b7-1f87980b1d0d"
	tokenSub := subID + ".sub"
	keySub := keys.WormholeAccessSubtoken(parentID, "foo")

	defaultArgs := args.TokenService{
		TokenHeader:       "x-token",
		TokenServiceAdmin: "pass1234",
	}

	ll := logs.InitializeDiscard()

	tests := map[string]struct {
		i            internal
		req          requests.RequestDetails
		tknCtx       wormhole.TokenContext
		wantSubtoken string
		assertError  func(*testing.T, *errs.StatusError)
	}{
		"no community id": {
			req: requests.RequestDetails{
				Headers: map[string]string{},
			},
			tknCtx: wormhole.TokenContext{
				TokenID: parentID,
				WAT:     tokenFoo,
				Payload: wormhole.TokenPayload{
					TokenID: parentID,
				},
			},
			assertError: func(t *testing.T, sErr *errs.StatusError) {
				assert.Nil(t, sErr)
			},
		},
		"existing subtoken": {
			req: requests.RequestDetails{
				Headers: map[string]string{
					keys.CommunityHeader: "foo",
				},
			},
			tknCtx: wormhole.TokenContext{
				TokenID: subID,
				WAT:     tokenSub,
				Payload: wormhole.TokenPayload{
					ExternalID: "foo",
					ParentID:   parentID,
					TokenID:    subID,
				},
			},
			assertError: func(t *testing.T, sErr *errs.StatusError) {
				assert.Nil(t, sErr)
			},
			wantSubtoken: tokenSub,
		},
		"cache hit": {
			i: internal{
				tokenSvcArgs: defaultArgs,
				kvStore: func() streams.KVStore {
					m := mock_streams.NewMockKVStore(ctrl)
					m.EXPECT().Get(gomock.Any(), keySub, gomock.Any()).Return(nil).Do(
						func(_ context.Context, _ string, v any) {
							if cs, ok := v.(*subtokenCache); ok {
								cs.Token = tokenSub
								cs.ID = subID
								cs.ParentID = parentID
								cs.ExternalID = "foo"
								cs.Exp = wormhole.FloatTime{Time: time.Now().Add(time.Hour)}
							}
						})
					return m
				}(),
			},
			req: requests.RequestDetails{
				Headers: map[string]string{
					keys.CommunityHeader: "foo",
				},
			},
			tknCtx: wormhole.TokenContext{
				TokenID: parentID,
				WAT:     tokenFoo,
				Payload: wormhole.TokenPayload{
					TokenID: parentID,
					Exp:     wormhole.FloatTime{Time: time.Now().Add(time.Hour)},
				},
			},
			assertError: func(t *testing.T, sErr *errs.StatusError) {
				assert.Nil(t, sErr)
			},
			wantSubtoken: tokenSub,
		},
		"cache expired": {
			i: internal{
				tokenSvcArgs:   defaultArgs,
				subtokenReqURL: "https://localhost:8080/admin",
				client: func() requests.Client {
					m := mock_requests.NewMockClient(ctrl)
					m.EXPECT().PostJSONBody(gomock.Any(), "https://localhost:8080/admin/user", gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Do(
						func(_ context.Context, _ string, _ map[string]string, _ any, v any) {
							if resp, ok := v.(*subtokenResp); ok {
								resp.Token = tokenSub
							}
						})
					return m
				}(),
				kvStore: func() streams.KVStore {
					m := mock_streams.NewMockKVStore(ctrl)
					m.EXPECT().Get(gomock.Any(), keySub, gomock.Any()).Return(nil).Do(
						func(_ context.Context, _ string, v any) {
							if cs, ok := v.(*subtokenCache); ok {
								cs.Token = tokenSub
								cs.ID = subID
								cs.ParentID = parentID
								cs.ExternalID = "foo"
								cs.Exp = wormhole.FloatTime{Time: time.Now().Add(-time.Hour)}
							}
						})
					m.EXPECT().Delete(gomock.Any(), keySub).Return(nil)
					m.EXPECT().Put(gomock.Any(), keySub, gomock.Any()).Return(nil)
					return m
				}(),
			},
			req: requests.RequestDetails{
				Headers: map[string]string{
					keys.CommunityHeader: "foo",
				},
			},
			tknCtx: wormhole.TokenContext{
				TokenID: parentID,
				WAT:     tokenFoo,
				Payload: wormhole.TokenPayload{
					Username: "user",
					TokenID:  parentID,
					Exp: wormhole.FloatTime{
						Time: time.Now().Add(time.Hour),
					},
				},
			},
			assertError: func(t *testing.T, sErr *errs.StatusError) {
				assert.Nil(t, sErr)
			},
			wantSubtoken: tokenSub,
		},
		"no-cache": {
			i: internal{
				tokenSvcArgs:   defaultArgs,
				subtokenReqURL: "https://localhost:8080/admin",
				client: func() requests.Client {
					m := mock_requests.NewMockClient(ctrl)
					m.EXPECT().PostJSONBody(gomock.Any(), "https://localhost:8080/admin/user", gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Do(
						func(_ context.Context, _ string, headers map[string]string, _ any, v any) {
							if headers["x-token"] != defaultArgs.TokenServiceAdmin {
								t.Fail()
							}

							if resp, ok := v.(*subtokenResp); ok {
								resp.Token = tokenSub
							}
						})
					return m
				}(),
				kvStore: func() streams.KVStore {
					m := mock_streams.NewMockKVStore(ctrl)
					m.EXPECT().Get(gomock.Any(), keySub, gomock.Any()).Return(errors.New("not found"))
					m.EXPECT().Put(gomock.Any(), keySub, gomock.Any()).Return(nil)
					return m
				}(),
			},
			req: requests.RequestDetails{
				Headers: map[string]string{
					keys.CommunityHeader: "foo",
				},
			},
			tknCtx: wormhole.TokenContext{
				TokenID: parentID,
				WAT:     tokenFoo,
				Payload: wormhole.TokenPayload{
					Username: "user",
					TokenID:  parentID,
					Exp: wormhole.FloatTime{
						Time: time.Now().Add(time.Hour),
					},
				},
			},
			assertError: func(t *testing.T, sErr *errs.StatusError) {
				assert.Nil(t, sErr)
			},
			wantSubtoken: tokenSub,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := tt.i.SubtokenFlow(t.Context(), ll, tt.req, tt.tknCtx)

			tt.assertError(t, err)
			assert.Equal(t, tt.wantSubtoken, got)
		})
	}
}

func Test_buildSubtokenReq(t *testing.T) {
	t.Run("standard", func(t *testing.T) {
		got := buildSubtokenReq(
			wormhole.TokenContext{
				Payload: wormhole.TokenPayload{
					TokenID: "123",
				},
			},
			"foo",
		)

		assert.Equal(t, "subtoken", got.Token.Name)
		assert.Equal(t, "123", got.ParentID)
		assert.Equal(t, "foo", got.ExternalID)
	})
}
