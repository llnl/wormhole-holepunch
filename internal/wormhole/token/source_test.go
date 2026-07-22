package token

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/ctls/aescipher"
	"github.com/llnl/wormhole-holepunch/internal/ctls/errs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
	"github.com/llnl/wormhole-holepunch/internal/ctls/rules"
	"github.com/llnl/wormhole-holepunch/internal/ctls/streams"
	"github.com/llnl/wormhole-holepunch/internal/wormhole"
	"github.com/llnl/wormhole-holepunch/test/mocks/mock_requests"
	"github.com/llnl/wormhole-holepunch/test/mocks/mock_streams"
)

func Test_reqTokenKey(t *testing.T) {
	t.Run("key", func(t *testing.T) {
		got := keys.WormholeAccessToken("test")
		assert.Equal(t, "wat.v1.dGVzdA", got)
	})
}

func Test_internal_retrieveWAT(t *testing.T) {
	i := internal{
		tokenSvcArgs: args.TokenService{
			TokenHeader: tokenHeader,
		},
		cipher:    aescipher.NoopCipher{},
		validator: rules.NewValidator(),
	}

	tests := map[string]struct {
		req    requests.RequestDetails
		assert func(*testing.T, wormhole.TokenContext, bool, *errs.StatusError)
	}{
		"simple": {
			req: requests.RequestDetails{
				Headers: map[string]string{
					tokenHeader: "109ff5d7-dae0-48c8-8fad-4341c2595829.foo",
				},
			},
			assert: func(t *testing.T, tknCtx wormhole.TokenContext, b bool, sErr *errs.StatusError) {
				assert.Equal(t, "109ff5d7-dae0-48c8-8fad-4341c2595829.foo", tknCtx.WAT)
				assert.True(t, b)
				assert.Nil(t, sErr)
			},
		},
		"empty string": {
			req: requests.RequestDetails{
				Headers: map[string]string{
					tokenHeader: "",
				},
			},
			assert: func(t *testing.T, _ wormhole.TokenContext, b bool, sErr *errs.StatusError) {
				assert.False(t, b)
				assert.Nil(t, sErr)
			},
		},
		"missing": {
			req: requests.RequestDetails{
				Headers: map[string]string{},
			},
			assert: func(t *testing.T, _ wormhole.TokenContext, b bool, sErr *errs.StatusError) {
				assert.False(t, b)
				assert.Nil(t, sErr)
			},
		},
		"gl token": {
			req: requests.RequestDetails{
				Headers: map[string]string{
					tokenHeader: "glpat-JoHRoiVVhjorjFRbUHbrkUForfcS2Aj7sWuoiE.11.123abcdef",
				},
			},
			assert: func(t *testing.T, _ wormhole.TokenContext, b bool, sErr *errs.StatusError) {
				assert.True(t, b)
				// Not a Wormhole token but technically meets validation requirements.
				assert.NotNil(t, sErr)
			},
		},
		"invalid": {
			req: requests.RequestDetails{
				Headers: map[string]string{
					tokenHeader: "$(example)",
				},
			},
			assert: func(t *testing.T, _ wormhole.TokenContext, b bool, sErr *errs.StatusError) {
				assert.True(t, b)
				assert.NotNil(t, sErr)
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, found, err := i.retrieveWAT(tt.req)

			tt.assert(t, got, found, err)
		})
	}
}

func Test_decodeTrustedJWT(t *testing.T) {
	t.Run("valid payload", func(t *testing.T) {
		got, err := decodeTrustedJWT("example.eyJzdWIiOiJmb28iLCJncm91cHMiOlsicHJvamVjdDEiLCJwcm9qZWN0MiJdLCJkdWlkIjoiMTIzNDU2Nzg5IiwiZXhwIjoyNjM1NjQ5ODUyLjU1NjY4M30.jwt")
		assert.Nil(t, err)
		assert.Equal(t, "foo", got.Username)
	})

	t.Run("missing segment", func(t *testing.T) {
		_, err := decodeTrustedJWT("example.")
		assert.NotNil(t, err)
	})

	t.Run("invalid decoding", func(t *testing.T) {
		_, err := decodeTrustedJWT("example.+123.jwt")
		assert.NotNil(t, err)
	})

	t.Run("failed unmarshal", func(t *testing.T) {
		_, err := decodeTrustedJWT("example.abc.jwt")
		assert.NotNil(t, err)
	})
}

func Test_internal_oauthFlow(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ll := logs.InitializeDiscard()

	key := "wos.v1-d1ee41918786372d0a719fedbdb30174188fe009252a0336b8bf3508f83f53ce"

	oauth2AuthURL, _ := url.Parse("http://example.com/oauth2/auth")
	oauth2RedirectURL, _ := url.Parse("http://example.com/oauth2/start")

	tests := map[string]struct {
		i             internal
		req           requests.RequestDetails
		assertError   func(*testing.T, *errs.StatusError)
		assertPayload func(*testing.T, wormhole.TokenPayload)
	}{
		"auth flow": {
			i: internal{
				oauth2Enabled: true,
				client: func() requests.Client {
					m := mock_requests.NewMockClient(ctrl)
					m.EXPECT().GetHeaders(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(
						map[string]string{
							keys.Oauth2ProxyAccessTokenHeader: "access.token.example",
						},
						nil,
					)
					m.EXPECT().GetJSON(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Do(
						func(_ context.Context, _ string, _ map[string]string, v any) {
							if e, ok := v.(*exchangeResp); ok {
								e.JWT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl9pZCI6ImM1MjBjMDhjLTAzMjUtNDhjNC04YmQxLTU3YmRlOGM3YzM4MiIsInN1YiI6ImZvbyIsImdyb3VwcyI6WyJwcm9qZWN0MSIsInByb2plY3QyIl0sImR1aWQiOiIxMjM0NTY3ODkiLCJleHAiOjI2MzU2NDk4NTIuNTU2NjgzfQ.placeholder"
							}
						})
					return m
				}(),
				kvStore: func() streams.KVStore {
					m := mock_streams.NewMockKVStore(ctrl)
					m.EXPECT().Get(gomock.Any(), key, gomock.Any()).Return(errors.New("not found"))
					m.EXPECT().Put(gomock.Any(), key, gomock.Any()).Return(nil)
					return m
				}(),
			},
			req: requests.RequestDetails{
				Headers: map[string]string{
					"cookie": "auth=session",
				},
			},
			assertError: func(t *testing.T, sErr *errs.StatusError) {
				assert.Nil(t, sErr)
			},
		},
		"invalid auth redirect": {
			i: internal{
				oauth2Enabled: true,
				client: func() requests.Client {
					m := mock_requests.NewMockClient(ctrl)
					m.EXPECT().GetHeaders(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(
						map[string]string{},
						&requests.RequestFailedError{},
					)
					return m
				}(),
			},
			req: requests.RequestDetails{
				Headers: map[string]string{
					"cookie": "auth=session",
				},
			},
			assertError: func(t *testing.T, sErr *errs.StatusError) {
				assert.ErrorContains(t, sErr, "redirect")
			},
		},
		"disabled": {
			i: internal{
				oauth2Enabled: false,
			},
			assertError: func(t *testing.T, sErr *errs.StatusError) {
				assert.ErrorContains(t, sErr, "oauth2 support currently disabled")
			},
		},
		"cache hit": {
			i: internal{
				oauth2Enabled: true,
				client: func() requests.Client {
					m := mock_requests.NewMockClient(ctrl)
					m.EXPECT().GetHeaders(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(
						map[string]string{
							keys.Oauth2ProxyAccessTokenHeader: "access.token.example",
						},
						nil,
					)
					return m
				}(),
				kvStore: func() streams.KVStore {
					m := mock_streams.NewMockKVStore(ctrl)
					m.EXPECT().Get(gomock.Any(), key, gomock.Any()).Return(nil).Do(
						func(_ context.Context, _ string, v any) {
							if cs, ok := v.(*cache); ok {
								cs.EncryptedToken = "access.token.example"
								cs.EncryptedJumpToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl9pZCI6ImM1MjBjMDhjLTAzMjUtNDhjNC04YmQxLTU3YmRlOGM3YzM4MiIsInN1YiI6ImZvbyIsImdyb3VwcyI6WyJwcm9qZWN0MSIsInByb2plY3QyIl0sImR1aWQiOiIxMjM0NTY3ODkiLCJleHAiOjI2MzU2NDk4NTIuNTU2NjgzfQ.placeholder"
								cs.Payload = wormhole.TokenPayload{
									TokenID:  "c520c08c-0325-48c4-8bd1-57bde8c7c382",
									Username: "foo",
									Groups:   []string{"project1", "project2"},
									Exp:      wormhole.FloatTime{Time: time.Now().Add(time.Hour)},
								}
							}
						})
					return m
				}(),
			},
			req: requests.RequestDetails{
				Headers: map[string]string{
					"cookie": "auth=session",
				},
			},
			assertError: func(t *testing.T, sErr *errs.StatusError) {
				assert.Nil(t, sErr)
			},
			assertPayload: func(t *testing.T, tp wormhole.TokenPayload) {
				assert.Equal(t, "c520c08c-0325-48c4-8bd1-57bde8c7c382", tp.TokenID)
				assert.Equal(t, "foo", tp.Username)
			},
		},
		"cache miss": {
			i: internal{
				oauth2Enabled: true,
				client: func() requests.Client {
					m := mock_requests.NewMockClient(ctrl)
					m.EXPECT().GetHeaders(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(
						map[string]string{
							keys.Oauth2ProxyAccessTokenHeader: "access.token.example",
						},
						nil,
					)
					return m
				}(),
				kvStore: func() streams.KVStore {
					m := mock_streams.NewMockKVStore(ctrl)
					m.EXPECT().Get(gomock.Any(), key, gomock.Any()).Return(nil).Do(
						func(_ context.Context, _ string, v any) {
							if cs, ok := v.(*cache); ok {
								cs.EncryptedToken = "access.token.old"
								cs.EncryptedJumpToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl9pZCI6ImM1MjBjMDhjLTAzMjUtNDhjNC04YmQxLTU3YmRlOGM3YzM4MiIsInN1YiI6ImZvbyIsImdyb3VwcyI6WyJwcm9qZWN0MSIsInByb2plY3QyIl0sImR1aWQiOiIxMjM0NTY3ODkiLCJleHAiOjI2MzU2NDk4NTIuNTU2NjgzfQ.placeholder"
								cs.Payload = wormhole.TokenPayload{
									TokenID:  "c520c08c-0325-48c4-8bd1-57bde8c7c382",
									Username: "foo",
									Groups:   []string{"project1", "project2"},
									Exp:      wormhole.FloatTime{Time: time.Now().Add(time.Hour)},
								}
							}
						})
					return m
				}(),
			},
			req: requests.RequestDetails{
				Headers: map[string]string{
					"cookie": "auth=session",
				},
			},
			assertError: func(t *testing.T, sErr *errs.StatusError) {
				assert.ErrorContains(t, sErr, "redirect")
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tt.i.cipher = aescipher.NoopCipher{}
			tt.i.oauth2RedirectURL = oauth2RedirectURL
			tt.i.oauth2AuthURL = oauth2AuthURL

			got, _, err := tt.i.oauthFlow(t.Context(), ll, tt.req)

			tt.assertError(t, err)

			if tt.assertPayload != nil {
				tt.assertPayload(t, got)
			}
		})
	}
}
