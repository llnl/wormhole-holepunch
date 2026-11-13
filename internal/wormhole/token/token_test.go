package token

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/ctls/aescipher"
	"github.com/llnl/wormhole-holepunch/internal/ctls/errs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
	"github.com/llnl/wormhole-holepunch/internal/ctls/rules"
	"github.com/llnl/wormhole-holepunch/internal/ctls/streams"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr"
	"github.com/llnl/wormhole-holepunch/internal/wormhole"
	"github.com/llnl/wormhole-holepunch/test/mocks/mock_logs"
	"github.com/llnl/wormhole-holepunch/test/mocks/mock_requests"
	"github.com/llnl/wormhole-holepunch/test/mocks/mock_streams"
)

const (
	tarURL      = "https://example.com"
	tokenHeader = "x-token"
)

func Test_Initialize(t *testing.T) {
	t.Run("standard", func(t *testing.T) {
		got := Initialize(
			&aescipher.NoopCipher{},
			nil,
			logs.InitializeDiscard(),
			args.TokenService{
				TokenHost:         "https://example.com/",
				OauthExchangePath: "/oauth",
				TokenExchangePath: "/token",
				SubtokenPath:      "/subtoken",
			},
			oauthmngr.Disabled(),
		)

		assert.Equal(t, "https://example.com/token", got.(internal).tokenExchangeURL)
	})

	t.Run("oauth validator", func(t *testing.T) {
		got := Initialize(
			&aescipher.NoopCipher{},
			nil,
			logs.InitializeDiscard(),
			args.TokenService{TokenHost: "https://example.com/", OauthExchangePath: "/oauth"},
			oauthmngr.Disabled(),
		).(internal)

		assert.Equal(t, oauthmngr.Disabled(), got.oauth)
		assert.Equal(t, "https://example.com/oauth", got.oauthExchangeURL)
	})
}

func Test_internal_RequestHeader_oauthCookies(t *testing.T) {
	ctrl := gomock.NewController(t)
	ll := logs.InitializeDiscard()
	key := "wos.v1-d1ee41918786372d0a719fedbdb30174188fe009252a0336b8bf3508f83f53ce"

	run := func(t *testing.T, cookieHeader string) AuthResponse {
		t.Helper()

		i := internal{
			oauth: &stubValidator{result: oauthmngr.Result{
				AccessToken:  "access.token.example",
				CookieHeader: cookieHeader,
			}},
			kvStore:      cachedSession(ctrl, key, "access.token.example"),
			cipher:       aescipher.NoopCipher{},
			tokenSvcArgs: args.TokenService{TokenHeader: tokenHeader},
			validator:    rules.NewValidator(),
		}

		_, resp, sErr := i.RequestHeader(t.Context(), ll, requests.RequestDetails{
			Headers: map[string]string{"cookie": "_oauth2_proxy=session; " + cookieHeader},
		})
		assert.Nil(t, sErr)

		return resp
	}

	t.Run("forwards the cookie header with the session stripped", func(t *testing.T) {
		resp := run(t, "other=1")

		assert.Equal(t, "other=1", resp.SetHeaders[keys.CookieHeader])
		assert.Empty(t, resp.RemoveHeaders)
	})

	t.Run("removes the cookie header when nothing remains", func(t *testing.T) {
		resp := run(t, "")

		assert.NotContains(t, resp.SetHeaders, keys.CookieHeader)
		assert.Equal(t, []string{keys.CookieHeader}, resp.RemoveHeaders)
	})
}

func Test_internal_RequestHeader_WATCookies(t *testing.T) {
	for _, strategy := range []string{
		oauthmngr.StrategyOauth2ProxyMiddleware,
		oauthmngr.StrategyOauth2ProxyReverse,
		oauthmngr.StrategyNone,
	} {
		t.Run(strategy, func(t *testing.T) {
			for _, onlySession := range []bool{false, true} {
				t.Run(fmt.Sprintf("onlySession=%t", onlySession), func(t *testing.T) {
					ctrl := gomock.NewController(t)
					ll := logs.InitializeDiscard()
					oauth, err := oauthmngr.Initialize(nil, nil, ll, args.OauthManagement{
						Strategy: strategy, InternalProxyURL: "http://proxy:4180",
						UserAuthURL: "auth.example.com", OauthLedgerURL: "http://ledger:8083",
						NonceTTL: 300, ProxyCookieName: "_custom_proxy", CookieName: "_custom_session",
					})
					require.NoError(t, err)

					id := "c520c08c-0325-48c4-8bd1-57bde8c7c382"
					wat := id + ".foo"
					header := "_custom_proxy=p; _custom_proxy_0=x; _custom_proxy_12=y"
					if strategy == oauthmngr.StrategyOauth2ProxyMiddleware {
						header += "; _custom_session=s; _custom_session_0=x"
					}
					if !onlySession {
						header += "; app=keep"
					}
					i := internal{
						oauth: oauth, cipher: aescipher.NoopCipher{},
						kvStore:      cachedSession(ctrl, keys.WormholeAccessToken(id), wat),
						tokenSvcArgs: args.TokenService{TokenHeader: tokenHeader},
						validator:    rules.NewValidator(),
					}
					_, resp, sErr := i.RequestHeader(t.Context(), ll, requests.RequestDetails{
						Headers: map[string]string{tokenHeader: wat, keys.CookieHeader: header},
					})
					require.Nil(t, sErr)
					if strategy == oauthmngr.StrategyNone {
						assert.NotContains(t, resp.SetHeaders, keys.CookieHeader)
						assert.Empty(t, resp.RemoveHeaders)
					} else if onlySession {
						assert.NotContains(t, resp.SetHeaders, keys.CookieHeader)
						assert.Equal(t, []string{keys.CookieHeader}, resp.RemoveHeaders)
					} else {
						assert.Equal(t, "app=keep", resp.SetHeaders[keys.CookieHeader])
						assert.Empty(t, resp.RemoveHeaders)
					}
				})
			}
		})
	}
}

func Test_internal_RequestHeader(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	idFoo := "c520c08c-0325-48c4-8bd1-57bde8c7c382"
	tokenFoo := idFoo + ".foo"
	keyFoo := keys.WormholeAccessToken(idFoo)

	ll := logs.InitializeDiscard()

	tests := map[string]struct {
		i             internal
		req           requests.RequestDetails
		assertError   func(*testing.T, *errs.StatusError)
		assertReturns func(*testing.T, wormhole.TokenContext, AuthResponse)
	}{
		"successful token": {
			i: internal{
				client: func() *mock_requests.MockClient {
					m := mock_requests.NewMockClient(ctrl)
					m.EXPECT().GetJSON(gomock.Any(), tarURL+"/token/jwt", gomock.Any(), gomock.Any()).Return(nil).Do(
						func(_ context.Context, _ string, _ map[string]string, v any) {
							if e, ok := v.(*exchangeResp); ok {
								e.JWT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl9pZCI6ImM1MjBjMDhjLTAzMjUtNDhjNC04YmQxLTU3YmRlOGM3YzM4MiIsInN1YiI6ImZvbyIsImdyb3VwcyI6WyJwcm9qZWN0MSIsInByb2plY3QyIl0sImR1aWQiOiIxMjM0NTY3ODkiLCJleHAiOjI2MzU2NDk4NTIuNTU2NjgzfQ.placeholder"
							}
						})
					return m
				}(),
				kvStore: func() streams.KVStore {
					key := keyFoo
					m := mock_streams.NewMockKVStore(ctrl)
					m.EXPECT().Get(gomock.Any(), key, gomock.Any()).Return(errors.New("not found"))
					m.EXPECT().Put(gomock.Any(), key, gomock.Any()).Return(nil)
					return m
				}(),
				tokenSvcArgs: args.TokenService{
					TokenHeader: tokenHeader,
				},
				tokenExchangeURL: tarURL + "/token/jwt",
				validator:        rules.NewValidator(),
			},
			req: requests.RequestDetails{
				Headers: map[string]string{
					tokenHeader: tokenFoo,
				},
			},
			assertError: func(t *testing.T, sErr *errs.StatusError) {
				assert.Nil(t, sErr)
			},
			assertReturns: func(t *testing.T, tknCtx wormhole.TokenContext, ar AuthResponse) {
				assert.Equal(t, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl9pZCI6ImM1MjBjMDhjLTAzMjUtNDhjNC04YmQxLTU3YmRlOGM3YzM4MiIsInN1YiI6ImZvbyIsImdyb3VwcyI6WyJwcm9qZWN0MSIsInByb2plY3QyIl0sImR1aWQiOiIxMjM0NTY3ODkiLCJleHAiOjI2MzU2NDk4NTIuNTU2NjgzfQ.placeholder", ar.SetHeaders[tokenHeader])
				assert.Equal(t, "foo", tknCtx.Payload.Username)
				assert.Len(t, tknCtx.Payload.Groups, 2)
			},
		},
		"caching service errors": {
			i: internal{
				client: func() *mock_requests.MockClient {
					m := mock_requests.NewMockClient(ctrl)
					m.EXPECT().GetJSON(gomock.Any(), tarURL+"/token/jwt", gomock.Any(), gomock.Any()).Return(nil).Do(
						func(_ context.Context, _ string, _ map[string]string, v any) {
							if e, ok := v.(*exchangeResp); ok {
								e.JWT = "example.eyJzdWIiOiJ1c2VybmFtZSIsImdyb3VwcyI6WyJwcm9qMTIzIiwiZ3JwNDU2Il19.jwt"
							}
						})
					return m
				}(),
				kvStore: func() streams.KVStore {
					key := keyFoo
					m := mock_streams.NewMockKVStore(ctrl)
					m.EXPECT().Get(gomock.Any(), key, gomock.Any()).Return(errors.New("internal error..."))
					m.EXPECT().Put(gomock.Any(), key, gomock.Any()).Return(errors.New("internal error..."))
					return m
				}(),
				tokenSvcArgs: args.TokenService{
					TokenHeader: tokenHeader,
				},
				tokenExchangeURL: tarURL + "/token/jwt",
				validator:        rules.NewValidator(),
			},
			req: requests.RequestDetails{
				Headers: map[string]string{
					tokenHeader: tokenFoo,
				},
			},
			assertError: func(t *testing.T, sErr *errs.StatusError) {
				assert.Nil(t, sErr)
			},
			assertReturns: func(t *testing.T, tknCtx wormhole.TokenContext, ar AuthResponse) {
				assert.Equal(t, "example.eyJzdWIiOiJ1c2VybmFtZSIsImdyb3VwcyI6WyJwcm9qMTIzIiwiZ3JwNDU2Il19.jwt", ar.SetHeaders[tokenHeader])
				assert.Equal(t, "username", tknCtx.Payload.Username)
				assert.Len(t, tknCtx.Payload.Groups, 2)
			},
		},
		"unauthorized request (401)": {
			i: internal{
				client: func() *mock_requests.MockClient {
					m := mock_requests.NewMockClient(ctrl)
					m.EXPECT().GetJSON(gomock.Any(), tarURL+"/token/jwt", gomock.Any(), gomock.Any()).Return(
						&requests.RequestFailedError{Err: errors.New("message"), StatusCode: http.StatusUnauthorized})
					return m
				}(),
				kvStore: func() streams.KVStore {
					m := mock_streams.NewMockKVStore(ctrl)
					m.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("not found"))
					m.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
					return m
				}(),
				tokenSvcArgs: args.TokenService{
					TokenHeader: tokenHeader,
				},
				tokenExchangeURL: tarURL + "/token/jwt",
				validator:        rules.NewValidator(),
			},
			req: requests.RequestDetails{
				Headers: map[string]string{
					tokenHeader: "c520c08c-0325-48c4-8bd1-57bde8c7c382.invalidToken",
				},
			},
			assertError: func(t *testing.T, sErr *errs.StatusError) {
				assert.NotNil(t, sErr)
			},
		},
		"unauthorized request (500)": {
			i: internal{
				client: func() *mock_requests.MockClient {
					m := mock_requests.NewMockClient(ctrl)
					m.EXPECT().GetJSON(gomock.Any(), tarURL+"/token/jwt", gomock.Any(), gomock.Any()).Return(
						&requests.RequestFailedError{Err: errors.New("message"), StatusCode: http.StatusInternalServerError})
					return m
				}(),
				kvStore: func() streams.KVStore {
					m := mock_streams.NewMockKVStore(ctrl)
					m.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("not found"))
					// Due to the 500 status from the Token Service the ID should not be invalidated in the cache.
					// m.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
					return m
				}(),
				tokenSvcArgs: args.TokenService{
					TokenHeader: tokenHeader,
				},
				tokenExchangeURL: tarURL + "/token/jwt",
				validator:        rules.NewValidator(),
			},
			req: requests.RequestDetails{
				Headers: map[string]string{
					tokenHeader: "c520c08c-0325-48c4-8bd1-57bde8c7c382.invalidToken",
				},
			},
			assertError: func(t *testing.T, sErr *errs.StatusError) {
				assert.NotNil(t, sErr)
			},
		},
		"bad token": {
			i: internal{
				tokenSvcArgs: args.TokenService{
					TokenHeader: tokenHeader,
				},
				tokenExchangeURL: tarURL + "/token/jwt",
				validator:        rules.NewValidator(),
			},
			req: requests.RequestDetails{
				Headers: map[string]string{
					tokenHeader: "$(example)",
				},
			},
			assertError: func(t *testing.T, sErr *errs.StatusError) {
				assert.ErrorContains(t, sErr, "validation")
			},
		},
		"cache hit": {
			i: internal{
				kvStore: func() streams.KVStore {
					key := keyFoo
					m := mock_streams.NewMockKVStore(ctrl)
					m.EXPECT().Get(gomock.Any(), key, gomock.Any()).Return(nil).Do(
						func(_ context.Context, _ string, v any) {
							if cs, ok := v.(*cache); ok {
								cs.EncryptedToken = tokenFoo
								cs.EncryptedJumpToken = "example.eyJzdWIiOiJ1c2VybmFtZSIsImdyb3VwcyI6WyJwcm9qMTIzIiwiZ3JwNDU2Il19.jwt"
								cs.Payload = wormhole.TokenPayload{
									Username: "username",
									Groups:   []string{"foo", "bar"},
									Exp:      wormhole.FloatTime{Time: time.Now().Add(time.Hour)},
								}
							}
						})
					return m
				}(),
				tokenSvcArgs: args.TokenService{
					TokenHeader: tokenHeader,
				},
				tokenExchangeURL: tarURL + "/token/jwt",
				validator:        rules.NewValidator(),
			},
			req: requests.RequestDetails{
				Headers: map[string]string{
					tokenHeader: tokenFoo,
				},
			},
			assertError: func(t *testing.T, sErr *errs.StatusError) {
				assert.Nil(t, sErr)
			},
			assertReturns: func(t *testing.T, tknCtx wormhole.TokenContext, ar AuthResponse) {
				assert.Equal(t, "example.eyJzdWIiOiJ1c2VybmFtZSIsImdyb3VwcyI6WyJwcm9qMTIzIiwiZ3JwNDU2Il19.jwt", ar.SetHeaders[tokenHeader])
				assert.Equal(t, "username", tknCtx.Payload.Username)
				assert.Len(t, tknCtx.Payload.Groups, 2)
			},
		},
		"cache hit (token miss-match)": {
			i: internal{
				kvStore: func() streams.KVStore {
					key := keyFoo
					m := mock_streams.NewMockKVStore(ctrl)
					m.EXPECT().Get(gomock.Any(), key, gomock.Any()).Return(nil).Do(
						func(_ context.Context, _ string, v any) {
							if cs, ok := v.(*cache); ok {
								cs.EncryptedToken = idFoo + ".bar"
								cs.EncryptedJumpToken = "example.eyJzdWIiOiJ1c2VybmFtZSIsImdyb3VwcyI6WyJwcm9qMTIzIiwiZ3JwNDU2Il19.jwt"
								cs.Payload = wormhole.TokenPayload{
									Username: "username",
									Groups:   []string{"foo", "bar"},
									Exp:      wormhole.FloatTime{Time: time.Now().Add(time.Hour)},
								}
							}
						})
					return m
				}(),
				tokenSvcArgs: args.TokenService{
					TokenHeader: tokenHeader,
				},
				tokenExchangeURL: tarURL + "/token/jwt",
				validator:        rules.NewValidator(),
			},
			req: requests.RequestDetails{
				Headers: map[string]string{
					tokenHeader: tokenFoo,
				},
			},
			assertError: func(t *testing.T, sErr *errs.StatusError) {
				assert.NotNil(t, sErr)
			},
		},
		"cache expired": {
			i: internal{
				kvStore: func() streams.KVStore {
					key := keyFoo
					m := mock_streams.NewMockKVStore(ctrl)
					m.EXPECT().Get(gomock.Any(), key, gomock.Any()).Return(nil).Do(
						func(_ context.Context, _ string, v any) {
							if cs, ok := v.(*cache); ok {
								cs.decryptedJumpToken = "example.eyJzdWIiOiJ1c2VybmFtZSIsImdyb3VwcyI6WyJwcm9qMTIzIiwiZ3JwNDU2Il19.jwt"
								cs.Payload = wormhole.TokenPayload{
									Username: "username",
									Groups:   []string{"foo", "bar"},
									Exp:      wormhole.FloatTime{Time: time.Now().Add(-time.Hour)},
								}
								cs.decryptedToken = "token12345"
							}
						})
					m.EXPECT().Delete(gomock.Any(), key).Return(nil)
					return m
				}(),
				tokenSvcArgs: args.TokenService{
					TokenHeader: tokenHeader,
				},
				tokenExchangeURL: tarURL + "/token/jwt",
				validator:        rules.NewValidator(),
			},
			req: requests.RequestDetails{
				Headers: map[string]string{
					tokenHeader: tokenFoo,
				},
			},
			assertError: func(t *testing.T, sErr *errs.StatusError) {
				assert.ErrorContains(t, sErr, "invalid credentials")
			},
		},
		"cache disallowed": {
			i: internal{
				kvStore: func() streams.KVStore {
					key := keyFoo
					m := mock_streams.NewMockKVStore(ctrl)
					m.EXPECT().Get(gomock.Any(), key, gomock.Any()).Return(nil).Do(
						func(_ context.Context, _ string, v any) {
							if cs, ok := v.(*cache); ok {
								cs.Disallowed = true
							}
						})
					return m
				}(),
				tokenSvcArgs: args.TokenService{
					TokenHeader: tokenHeader,
				},
				tokenExchangeURL: tarURL + "/token/jwt",
				validator:        rules.NewValidator(),
			},
			req: requests.RequestDetails{
				Headers: map[string]string{
					tokenHeader: tokenFoo,
				},
			},
			assertError: func(t *testing.T, sErr *errs.StatusError) {
				assert.ErrorContains(t, sErr, "invalid credentials")
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tt.i.cipher = aescipher.NoopCipher{}

			gotUP, gotAR, err := tt.i.RequestHeader(t.Context(), ll, tt.req)

			tt.assertError(t, err)
			if tt.assertReturns != nil {
				tt.assertReturns(t, gotUP, gotAR)
			}
		})
	}
}

func Test_internal_InvalidateToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	idFoo := "c520c08c-0325-48c4-8bd1-57bde8c7c382"
	keyFoo := keys.WormholeAccessToken(idFoo)

	tests := map[string]struct {
		i internal
	}{
		"successful": {
			i: internal{
				kvStore: func() streams.KVStore {
					m := mock_streams.NewMockKVStore(ctrl)
					m.EXPECT().Put(gomock.Any(), keyFoo, gomock.Any()).Return(nil)
					return m
				}(),
				ll: func() logs.Logger {
					m := mock_logs.NewMockLogger(ctrl)
					m.EXPECT().StartSpan(gomock.Any(), "RemoveToken").Return(t.Context(), func() {})
					m.EXPECT().DebugCtx(gomock.Any(), gomock.Any())
					return m
				}(),
			},
		},
		"failed request": {
			i: internal{
				kvStore: func() streams.KVStore {
					m := mock_streams.NewMockKVStore(ctrl)
					m.EXPECT().Put(gomock.Any(), keyFoo, gomock.Any()).Return(errors.New("error msg"))
					return m
				}(),
				ll: func() logs.Logger {
					m := mock_logs.NewMockLogger(ctrl)
					m.EXPECT().StartSpan(gomock.Any(), "RemoveToken").Return(t.Context(), func() {})
					m.EXPECT().InfoCtx(gomock.Any(), gomock.Any())
					return m
				}(),
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tt.i.InvalidateToken(t.Context(), idFoo)
		})
	}
}

func Test_internal_RemoveSubtoken(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	idFoo := "c520c08c-0325-48c4-8bd1-57bde8c7c382"
	keyFoo := keys.WormholeAccessToken(idFoo)

	idParent := "parent"
	idExt := "external"
	keySub := keys.WormholeAccessSubtoken(idParent, idExt)

	tests := map[string]struct {
		i internal
	}{
		"successful": {
			i: internal{
				kvStore: func() streams.KVStore {
					m := mock_streams.NewMockKVStore(ctrl)
					m.EXPECT().Put(gomock.Any(), keyFoo, gomock.Any()).Return(nil)
					m.EXPECT().Delete(gomock.Any(), keySub).Return(nil)
					return m
				}(),
				ll: func() logs.Logger {
					m := mock_logs.NewMockLogger(ctrl)
					m.EXPECT().StartSpan(gomock.Any(), "RemoveSubtoken").Return(t.Context(), func() {})
					m.EXPECT().StartSpan(gomock.Any(), "RemoveToken").Return(t.Context(), func() {})
					m.EXPECT().DebugCtx(gomock.Any(), gomock.Any()).Times(2)
					return m
				}(),
			},
		},
		"failed request": {
			i: internal{
				kvStore: func() streams.KVStore {
					m := mock_streams.NewMockKVStore(ctrl)
					m.EXPECT().Put(gomock.Any(), keyFoo, gomock.Any()).Return(nil)
					m.EXPECT().Delete(gomock.Any(), keySub).Return(errors.New("error msg"))
					return m
				}(),
				ll: func() logs.Logger {
					m := mock_logs.NewMockLogger(ctrl)
					m.EXPECT().StartSpan(gomock.Any(), "RemoveSubtoken").Return(t.Context(), func() {})
					m.EXPECT().StartSpan(gomock.Any(), "RemoveToken").Return(t.Context(), func() {})
					m.EXPECT().DebugCtx(gomock.Any(), gomock.Any())
					m.EXPECT().InfoCtx(gomock.Any(), gomock.Any())
					return m
				}(),
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tt.i.RemoveSubtoken(t.Context(), idParent, idExt, idFoo)
		})
	}
}
