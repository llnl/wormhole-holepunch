package token

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc/codes"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/ctls/aescipher"
	"github.com/llnl/wormhole-holepunch/internal/ctls/errs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/paths"
	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
	"github.com/llnl/wormhole-holepunch/internal/ctls/rules"
	"github.com/llnl/wormhole-holepunch/internal/ctls/streams"
	"github.com/llnl/wormhole-holepunch/internal/oauthmngr"
	"github.com/llnl/wormhole-holepunch/internal/wormhole"
	"github.com/llnl/wormhole-holepunch/internal/wormhole/registry"
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

// stubValidator is a configurable oauthmngr.Validator.
type stubValidator struct {
	result         oauthmngr.Result
	err            *errs.StatusError
	redirect       string
	redirectCookie *http.Cookie
	redirectErr    *errs.StatusError
	gotTarget      string
}

func (*stubValidator) ExpandSources(r []registry.RawSource) []registry.RawSource { return r }

func (s *stubValidator) PrepareAuthRedirect(p string, _ requests.RequestDetails) (oauthmngr.AuthRedirect, *errs.StatusError) {
	s.gotTarget = p

	return oauthmngr.AuthRedirect{URL: s.redirect, SetCookie: s.redirectCookie}, s.redirectErr
}

func (s *stubValidator) ValidateCookies(context.Context, requests.RequestDetails) (oauthmngr.Result, *errs.StatusError) {
	return s.result, s.err
}

func (*stubValidator) WasmPluginConfig() (*oauthmngr.PluginConfig, bool) { return nil, false }

const testJumpToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl9pZCI6ImM1MjBjMDhjLTAzMjUtNDhjNC04YmQxLTU3YmRlOGM3YzM4MiIsInN1YiI6ImZvbyIsImdyb3VwcyI6WyJwcm9qZWN0MSIsInByb2plY3QyIl0sImR1aWQiOiIxMjM0NTY3ODkiLCJleHAiOjI2MzU2NDk4NTIuNTU2NjgzfQ.placeholder"

// cachedSession establishes a KV store holding a cached session for the access token.
func cachedSession(ctrl *gomock.Controller, key, accessToken string) streams.KVStore {
	m := mock_streams.NewMockKVStore(ctrl)
	m.EXPECT().Get(gomock.Any(), key, gomock.Any()).Return(nil).Do(
		func(_ context.Context, _ string, v any) {
			if cs, ok := v.(*cache); ok {
				cs.EncryptedToken = accessToken
				cs.EncryptedJumpToken = testJumpToken
				cs.Payload = wormhole.TokenPayload{
					TokenID:  "c520c08c-0325-48c4-8bd1-57bde8c7c382",
					Username: "foo",
					Groups:   []string{"project1", "project2"},
					Exp:      wormhole.FloatTime{Time: time.Now().Add(time.Hour)},
				}
			}
		})

	return m
}

func Test_internal_oauthFlow(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ll := logs.InitializeDiscard()

	key := "wos.v1-d1ee41918786372d0a719fedbdb30174188fe009252a0336b8bf3508f83f53ce"
	session := oauthmngr.Result{AccessToken: "access.token.example", CookieHeader: "other=1"}
	req := requests.RequestDetails{
		Host:    "app.example.com",
		Scheme:  "https",
		Path:    "/page?x=1",
		Headers: map[string]string{"cookie": "_oauth2_proxy=session; other=1"},
	}

	t.Run("exchanges the session access token", func(t *testing.T) {
		i := internal{
			oauth: &stubValidator{result: session},
			client: func() requests.Client {
				m := mock_requests.NewMockClient(ctrl)
				m.EXPECT().GetJSON(gomock.Any(), "/oauth", map[string]string{
					keys.Oauth2ProxyAccessTokenHeader: "access.token.example",
				}, gomock.Any()).Return(nil).Do(
					func(_ context.Context, _ string, _ map[string]string, v any) {
						if e, ok := v.(*exchangeResp); ok {
							e.JWT = testJumpToken
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
			oauthExchangeURL: "/oauth",
			cipher:           aescipher.NoopCipher{},
		}

		payload, jwt, got, sErr := i.oauthFlow(t.Context(), ll, req)

		assert.Nil(t, sErr)
		assert.Equal(t, "foo", payload.Username)
		assert.Equal(t, testJumpToken, jwt)
		assert.Equal(t, &session, got)
	})

	t.Run("cache hit", func(t *testing.T) {
		i := internal{
			oauth:   &stubValidator{result: session},
			kvStore: cachedSession(ctrl, key, "access.token.example"),
			cipher:  aescipher.NoopCipher{},
		}

		payload, _, got, sErr := i.oauthFlow(t.Context(), ll, req)

		assert.Nil(t, sErr)
		assert.Equal(t, "c520c08c-0325-48c4-8bd1-57bde8c7c382", payload.TokenID)
		assert.Equal(t, &session, got)
	})

	t.Run("invalid session starts a flow returning to the request", func(t *testing.T) {
		bindingCookie := &http.Cookie{
			Name:     "_wormhole_oauth_flow_nonce",
			Value:    "browser-proof",
			Path:     paths.CallbackPrefix,
			MaxAge:   300,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		}
		stub := &stubValidator{
			err:            errs.SimpleAuthErr(errors.New("no session")),
			redirect:       "https://auth.example.com/-/wormhole/oauth2/start?rd=x",
			redirectCookie: bindingCookie,
		}
		i := internal{oauth: stub}

		_, _, got, sErr := i.oauthFlow(t.Context(), ll, req)

		assert.Nil(t, got)
		redirect, url := sErr.RedirectRequired()
		assert.True(t, redirect)
		assert.Equal(t, "https://auth.example.com/-/wormhole/oauth2/start?rd=x", url)
		assert.Equal(t, "https://app.example.com/page?x=1", stub.gotTarget, "query string is retained")
		assert.Equal(t, bindingCookie.String(), sErr.Headers()[keys.SetCookieHeader])
		assert.Equal(t, "no-store", sErr.Headers()["cache-control"])
	})

	t.Run("cached token mismatch starts a flow", func(t *testing.T) {
		i := internal{
			oauth:   &stubValidator{result: session, redirect: "https://start"},
			kvStore: cachedSession(ctrl, key, "access.token.old"),
			cipher:  aescipher.NoopCipher{},
		}

		_, _, _, sErr := i.oauthFlow(t.Context(), ll, req)

		redirect, _ := sErr.RedirectRequired()
		assert.True(t, redirect)
	})

	t.Run("no flow available (none strategy) is unauthenticated", func(t *testing.T) {
		i := internal{oauth: &stubValidator{
			err:         errs.SimpleAuthErr(errors.New("oauth2 flow is not configured")),
			redirectErr: errs.SimpleInternalErr(errors.New("oauth2 flow is not configured")),
		}}

		_, _, _, sErr := i.oauthFlow(t.Context(), ll, req)

		redirect, _ := sErr.RedirectRequired()
		assert.False(t, redirect)
		assert.Equal(t, int32(codes.Unauthenticated), sErr.Code())
	})

	t.Run("internal failures never redirect", func(t *testing.T) {
		stub := &stubValidator{
			err:      errs.SimpleInternalErr(errors.New("oauth2-proxy unavailable")),
			redirect: "https://start",
		}
		i := internal{oauth: stub}

		_, _, _, sErr := i.oauthFlow(t.Context(), ll, req)

		redirect, _ := sErr.RedirectRequired()
		assert.False(t, redirect)
		assert.Equal(t, int32(codes.Internal), sErr.Code())
		assert.Empty(t, stub.gotTarget)
	})
}

func Test_requestURL(t *testing.T) {
	assert.Equal(t, "https://app.example.com/page?x=1",
		requestURL(requests.RequestDetails{Host: "app.example.com", Path: "/page?x=1"}))
	assert.Equal(t, "http://app.example.com/",
		requestURL(requests.RequestDetails{Scheme: "http", Host: "app.example.com", Path: "/"}))
}
