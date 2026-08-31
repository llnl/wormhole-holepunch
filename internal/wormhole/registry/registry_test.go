package registry

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/ctls/errs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
	"github.com/llnl/wormhole-holepunch/internal/wormhole"
	"github.com/llnl/wormhole-holepunch/test/mocks/mock_requests"
	"github.com/llnl/wormhole-holepunch/test/mocks/mock_streams"
)

const (
	tarURL        = "https://example.com"
	routeResponse = `[
  {
    "id": "3d6527b5-9013-4255-a7b0-fe02e57756dc",
    "dst": "https://piko.example.com",
    "src": "https://demo-src.example.com",
	"community_id": "4f85939f-f19d-4217-afae-701568b12221",
    "rules": {
      "allowed": {
        "users": [
          "user1",
		  "user2"
        ],
        "groups": [
		  "group1"
		]
      },
      "disallowed": {
        "users": [],
        "groups": [
			    "test-grp"
		    ]
      }
    }
  },
  {
    "id": "0f66bdbe-3f7a-4db4-99ac-2cef8c2d637d",
    "dst": "http://127.0.0.1:8080",
    "src": "https://example-pre.example.com",
    "rules": {
      "allowed": {
        "users": [],
        "groups": [
			    "test-grp"
		  ]
      },
      "disallowed": {
        "users": [],
        "groups": []
      }
    }
  }
]`
	badResponse = `[
  {
    "id": "no-a-uuid",
    "dst": "https://foo.example.com",
    "src": "https://wormhole.example.com",
    "rules": {
      "allowed": {
        "users": [
          "user1",
		      "user2"
        ],
        "groups": []
      },
      "disallowed": {
        "users": [],
        "groups": [
			    "test-grp"
		    ]
      }
    }
  }
]`
)

func establishTestRouter(t *testing.T, ctrl *gomock.Controller) Router {
	client := mock_requests.NewMockClient(ctrl)
	client.EXPECT().GetJSON(gomock.Any(), tarURL, map[string]string{}, gomock.Any()).DoAndReturn(
		func(_ context.Context, url string, _ map[string]string, v any) error {
			return json.Unmarshal([]byte(routeResponse), v)
		},
	).AnyTimes()

	routeRegArgs := args.RouteRegistry{
		RegistryHost: tarURL,
		StaticCfg:    "../../../test/data/static.yaml",
	}

	// Not currently required in a universal way across tests.
	routePS := mock_streams.NewMockPubSub(ctrl)

	got, err := Initialize(context.Background(), client, routePS, routeRegArgs, logs.InitializeDiscard())
	if err != nil {
		t.FailNow()
	}

	sources, _ := got.(*internal).request(t.Context())
	got.(*internal).updateCtls(sources)

	return got
}

type mockJetstreamMsg struct {
	b []byte
}

func (m mockJetstreamMsg) Data() []byte {
	return m.b
}

func (m mockJetstreamMsg) Headers() nats.Header                      { return nil }
func (m mockJetstreamMsg) Subject() string                           { return "" }
func (m mockJetstreamMsg) Reply() string                             { return "" }
func (m mockJetstreamMsg) Metadata() (*jetstream.MsgMetadata, error) { return nil, nil }
func (m mockJetstreamMsg) Ack() error                                { return nil }
func (m mockJetstreamMsg) DoubleAck(context.Context) error           { return nil }
func (m mockJetstreamMsg) Nak() error                                { return nil }
func (m mockJetstreamMsg) NakWithDelay(time.Duration) error          { return nil }
func (m mockJetstreamMsg) InProgress() error                         { return nil }
func (m mockJetstreamMsg) Term() error                               { return nil }
func (m mockJetstreamMsg) TermWithReason(string) error               { return nil }

//

func Test_Config_Initialize(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	maxRetry = 1
	waitRetry = 1 * time.Millisecond

	ctx := context.Background()
	ll := logs.InitializeDiscard()
	client := mock_requests.NewMockClient(ctrl)
	routePS := mock_streams.NewMockPubSub(ctrl)

	t.Run("valid static config", func(t *testing.T) {
		routeRegArgs := args.RouteRegistry{
			RegistryHost: "https://example.com",
			StaticCfg:    "../../../test/data/static.yaml",
		}

		got, err := Initialize(ctx, client, routePS, routeRegArgs, ll)

		assert.NoError(t, err)
		assert.GreaterOrEqual(t, len(got.(*internal).staticSrc), 2)
	})

	t.Run("missing config", func(t *testing.T) {
		routeRegArgs := args.RouteRegistry{
			RegistryHost: "https://example.com",
			StaticCfg:    t.TempDir() + "/missing.toml",
		}

		_, err := Initialize(ctx, client, routePS, routeRegArgs, ll)

		assert.Error(t, err)
	})

	t.Run("invalid url", func(t *testing.T) {
		routeRegArgs := args.RouteRegistry{
			RegistryHost: "https ://example.com",
		}

		_, err := Initialize(ctx, client, routePS, routeRegArgs, ll)

		assert.Error(t, err)
	})

	t.Run("valid admin allowlist", func(t *testing.T) {
		routeRegArgs := args.RouteRegistry{
			RegistryHost: "https://example.com",
			RedirectAllowList: []string{
				"https://foo-admin.example.com",
				"https://bar-admin.example.com/path",
			},
		}

		got, err := Initialize(ctx, client, routePS, routeRegArgs, ll)

		assert.NoError(t, err)
		assert.Len(t, got.(*internal).adminRedirectAllow, 2)
	})

	t.Run("invalid admin allowlist", func(t *testing.T) {
		routeRegArgs := args.RouteRegistry{
			RegistryHost: "https://example.com",
			RedirectAllowList: []string{
				`"https://example.com/%zz"`,
			},
		}

		_, err := Initialize(ctx, client, routePS, routeRegArgs, ll)

		assert.ErrorContains(t, err, "invalid redirect allowlist")
	})
}

func Test_internal_AsyncFetchSources(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	maxRetry = 1
	waitRetry = 1 * time.Millisecond

	i := establishTestRouter(t, ctrl).(*internal)

	t.Run("valid mappings", func(t *testing.T) {
		client := mock_requests.NewMockClient(ctrl)
		client.EXPECT().GetJSON(gomock.Any(), tarURL, map[string]string{}, gomock.Any()).DoAndReturn(
			func(_ context.Context, url string, _ map[string]string, v any) *requests.RequestFailedError {
				json.Unmarshal([]byte(routeResponse), v)

				return nil
			},
		)

		routePS := mock_streams.NewMockPubSub(ctrl)
		routePS.EXPECT().PublishSingleMsg(gomock.Any(), gomock.Any()).Return(nil)

		i.routePS = routePS
		i.client = client

		i.AsyncFetchSources()
		time.Sleep(1 * time.Second)

		ctls := i.proxyCtls["3d6527b5-9013-4255-a7b0-fe02e57756dc"]
		assert.Len(t, ctls.RequestHeaders, 0)
		assert.Equal(t, "4f85939f-f19d-4217-afae-701568b12221", ctls.CommunityID)
	})

	t.Run("bad response", func(t *testing.T) {
		client := mock_requests.NewMockClient(ctrl)
		client.EXPECT().GetJSON(gomock.Any(), tarURL, map[string]string{}, gomock.Any()).DoAndReturn(
			func(_ context.Context, url string, _ map[string]string, v any) *requests.RequestFailedError {
				json.Unmarshal([]byte(badResponse), v)

				return nil
			},
		)

		i.client = client

		i.AsyncFetchSources()
		time.Sleep(1 * time.Second)

		// No changes
		ctls := i.proxyCtls["3d6527b5-9013-4255-a7b0-fe02e57756dc"]
		assert.Len(t, ctls.RequestHeaders, 0)
		assert.Equal(t, "4f85939f-f19d-4217-afae-701568b12221", ctls.CommunityID)
	})

	t.Run("failed mappings", func(t *testing.T) {
		client := mock_requests.NewMockClient(ctrl)
		client.EXPECT().GetJSON(gomock.Any(), tarURL, map[string]string{}, gomock.Any()).Return(
			&requests.RequestFailedError{Err: errors.New("error msg")})

		i.client = client

		i.AsyncFetchSources()
		time.Sleep(1 * time.Second)

		// No changes
		ctls := i.proxyCtls["3d6527b5-9013-4255-a7b0-fe02e57756dc"]
		assert.Len(t, ctls.RequestHeaders, 0)
		assert.Equal(t, "4f85939f-f19d-4217-afae-701568b12221", ctls.CommunityID)
	})
}

func Test_internal_AuthorizeProxy(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ll := logs.InitializeDiscard()
	tr := establishTestRouter(t, ctrl)

	tests := map[string]struct {
		req       requests.RequestDetails
		tknCtx    wormhole.TokenContext
		assertErr func(*testing.T, *errs.StatusError)
	}{
		"correct subtoken": {
			req: requests.RequestDetails{
				Scheme:  "https",
				Path:    "",
				Host:    "demo-src.example.com",
				RouteID: "3d6527b5-9013-4255-a7b0-fe02e57756dc",
			},
			tknCtx: wormhole.TokenContext{
				Payload: wormhole.TokenPayload{
					Username:   "user1",
					Groups:     []string{"some_group"},
					ExternalID: "4f85939f-f19d-4217-afae-701568b12221",
				},
			},
			assertErr: func(t *testing.T, sErr *errs.StatusError) {
				assert.Nil(t, sErr)
			},
		},
		"incorrect subtoken": {
			req: requests.RequestDetails{
				Scheme:  "https",
				Path:    "",
				Host:    "demo-src.example.com",
				RouteID: "3d6527b5-9013-4255-a7b0-fe02e57756dc",
			},
			tknCtx: wormhole.TokenContext{
				Payload: wormhole.TokenPayload{
					Username:   "user1",
					Groups:     []string{"some_group"},
					ExternalID: "bar",
				},
			},
			assertErr: func(t *testing.T, sErr *errs.StatusError) {
				assert.ErrorContains(t, sErr, "subtoken")
			},
		},
		"allowed user": {
			req: requests.RequestDetails{
				Scheme:  "https",
				Path:    "",
				Host:    "demo-src.example.com",
				RouteID: "3d6527b5-9013-4255-a7b0-fe02e57756dc",
			},
			tknCtx: wormhole.TokenContext{
				Payload: wormhole.TokenPayload{
					Username: "user1",
					Groups:   []string{"some_group"},
				},
			},
			assertErr: func(t *testing.T, sErr *errs.StatusError) {
				assert.Nil(t, sErr)
			},
		},
		"missing piko header": {
			req: requests.RequestDetails{
				Scheme:  "https",
				Path:    "",
				Host:    "wormhole.example.com",
				Headers: map[string]string{},
			},
			assertErr: func(t *testing.T, sErr *errs.StatusError) {
				assert.ErrorContains(t, sErr, "Internal Server Error")
			},
		},
		"non-uuid header": {
			req: requests.RequestDetails{
				Scheme:  "https",
				Path:    "",
				Host:    "wormhole.example.com",
				RouteID: "$(example)",
			},
			assertErr: func(t *testing.T, sErr *errs.StatusError) {
				assert.ErrorContains(t, sErr, "Bad Request")
			},
		},
		"no matching": {
			req: requests.RequestDetails{
				Scheme:  "https",
				Path:    "",
				Host:    "wormhole.example.com",
				RouteID: uuid.Must(uuid.NewRandom()).String(),
			},
			assertErr: func(t *testing.T, sErr *errs.StatusError) {
				assert.ErrorContains(t, sErr, "no destination for")
			},
		},
		"disallowed group": {
			req: requests.RequestDetails{
				Scheme:  "https",
				Path:    "",
				Host:    "demo-src.example.com",
				RouteID: "3d6527b5-9013-4255-a7b0-fe02e57756dc",
			},
			tknCtx: wormhole.TokenContext{
				Payload: wormhole.TokenPayload{
					Username: "user1",
					Groups:   []string{"new-grp", "test-grp"},
				},
			},
			assertErr: func(t *testing.T, sErr *errs.StatusError) {
				assert.ErrorContains(t, sErr, "user group denied")
			},
		},
		"allowed group": {
			req: requests.RequestDetails{
				Scheme:  "https",
				Path:    "",
				Host:    "demo-src.example.com",
				RouteID: "3d6527b5-9013-4255-a7b0-fe02e57756dc",
			},
			tknCtx: wormhole.TokenContext{
				Payload: wormhole.TokenPayload{
					Username: "some_user",
					Groups:   []string{"group1"},
				},
			},
			assertErr: func(t *testing.T, sErr *errs.StatusError) {
				assert.Nil(t, sErr)
			},
		},
		"no matching user/group": {
			req: requests.RequestDetails{
				Scheme:  "https",
				Path:    "",
				Host:    "example-pre.example.com",
				RouteID: "0f66bdbe-3f7a-4db4-99ac-2cef8c2d637d",
			},
			tknCtx: wormhole.TokenContext{
				Payload: wormhole.TokenPayload{
					Username: "user1",
					Groups:   []string{"group1"},
				},
			},
			assertErr: func(t *testing.T, sErr *errs.StatusError) {
				assert.Error(t, sErr)
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := tr.AuthorizeProxy(t.Context(), ll, tt.req, tt.tknCtx)

			tt.assertErr(t, err)
		})
	}
}

func Test_internal_RefreshControls(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	i := establishTestRouter(t, ctrl).(*internal)

	t.Run("refresh from msg", func(t *testing.T) {
		m := mockJetstreamMsg{
			b: []byte(routeResponse),
		}

		i.RefreshControls(m)

		assert.GreaterOrEqual(t, len(i.authCtls), 3)
		assert.GreaterOrEqual(t, len(i.FetchProxyControls()), 3)
		assert.GreaterOrEqual(t, len(i.ReportControlsJSON()), 3)
	})

	t.Run("refresh include admin allowlist", func(t *testing.T) {
		m := mockJetstreamMsg{
			b: []byte(routeResponse),
		}

		i.adminRedirectAllow, _ = normalizeHostMap(
			[]string{
				"https://foo-admin.example.com",
				"https://bar-admin.example.com/path",
			},
		)

		i.RefreshControls(m)

		_, barAdmin := i.redirectAllow["bar-admin.example.com"]
		_, demoSrc := i.redirectAllow["example-pre.example.com"]
		_, random := i.redirectAllow["random.url.example.com"]

		assert.True(t, barAdmin)
		assert.True(t, demoSrc)
		assert.False(t, random)
	})

	t.Run("remove mapping", func(t *testing.T) {
		newResponse := `[
			  {
			    "id": "3d6527b5-9013-4255-a7b0-fe02e57756dc",
			    "dst": "https://foo.example.com",
			    "src": "https://demo-src.example.com",
			    "rules": {
			      "allowed": {
			        "users": [
			          "user1",
					      "user2"
			        ],
			        "groups": []
			      },
			      "disallowed": {
			        "users": [],
			        "groups": [
						    "test-grp"
					    ]
			      }
			    }
			  }
			]`

		m := mockJetstreamMsg{
			b: []byte(newResponse),
		}

		i.RefreshControls(m)

		assert.GreaterOrEqual(t, len(i.authCtls), 1)
		assert.GreaterOrEqual(t, len(i.FetchProxyControls()), 3)
	})
}

func Test_internal_PublishSources(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	maxRetry = 1
	waitRetry = 1 * time.Millisecond

	i := establishTestRouter(t, ctrl).(*internal)

	t.Run("valid mappings", func(t *testing.T) {
		client := mock_requests.NewMockClient(ctrl)
		client.EXPECT().GetJSON(gomock.Any(), tarURL, map[string]string{}, gomock.Any()).DoAndReturn(
			func(_ context.Context, url string, _ map[string]string, v any) *requests.RequestFailedError {
				json.Unmarshal([]byte(routeResponse), v)
				return nil
			},
		)

		routePS := mock_streams.NewMockPubSub(ctrl)
		routePS.EXPECT().PublishSingleMsg(gomock.Any(), gomock.Any()).Return(nil)

		i.routePS = routePS
		i.client = client

		err := i.PublishSources(t.Context())

		assert.Nil(t, err)

		ctls := i.proxyCtls["3d6527b5-9013-4255-a7b0-fe02e57756dc"]
		assert.Equal(t, "4f85939f-f19d-4217-afae-701568b12221", ctls.CommunityID)
	})
}

func Test_authControls_enforce(t *testing.T) {
	authCtls := authControls{
		Allowed: userDetails{
			Groups: map[string]struct{}{
				"allowed_grp_1": {},
				"allowed_grp_2": {},
				"both_grp":      {}, // present in both allow + disallow for priority testing
			},
			Users: map[string]struct{}{
				"allowed_usr_1": {},
				"allowed_usr_2": {},
				"allowed_usr_3": {},
				"both_usr":      {}, // present in both allow + disallow for priority testing
			},
		},
		Disallowed: userDetails{
			Groups: map[string]struct{}{
				"disallowed_grp_1": {},
				"disallowed_grp_2": {},
				"both_grp":         {},
			},
			Users: map[string]struct{}{
				"disallowed_usr_1": {},
				"both_usr":         {},
			},
		},
	}

	mkTknCtx := func(username string, groups ...string) wormhole.TokenContext {
		var tc wormhole.TokenContext
		tc.Payload.Username = username
		tc.Payload.Groups = groups
		return tc
	}

	tests := map[string]struct {
		tknCtx        wormhole.TokenContext
		errorContains string
	}{
		// 1. Explicit user deny
		"deny explicit user deny only": {
			tknCtx:        mkTknCtx("disallowed_usr_1"),
			errorContains: "user explicitly denied",
		},
		"deny explicit user deny overrides explicit user allow": {
			tknCtx:        mkTknCtx("both_usr"),
			errorContains: "user explicitly denied",
		},
		"deny explicit user deny overrides group deny": {
			tknCtx:        mkTknCtx("disallowed_usr_1", "disallowed_grp_1"),
			errorContains: "user explicitly denied",
		},
		"deny explicit user deny overrides group allow": {
			tknCtx:        mkTknCtx("disallowed_usr_1", "allowed_grp_1"),
			errorContains: "user explicitly denied",
		},

		// 2. Group deny
		"deny group deny only": {
			tknCtx:        mkTknCtx("unknown_usr", "disallowed_grp_1"),
			errorContains: "user group denied",
		},
		"deny group deny overrides explicit user allow": {
			tknCtx:        mkTknCtx("allowed_usr_1", "disallowed_grp_1"),
			errorContains: "user group denied",
		},
		"deny group deny overrides group allow same group": {
			tknCtx:        mkTknCtx("unknown_usr", "both_grp"),
			errorContains: "user group denied",
		},
		"deny group deny overrides another allowed group": {
			tknCtx:        mkTknCtx("unknown_usr", "allowed_grp_1", "disallowed_grp_1"),
			errorContains: "user group denied",
		},

		// 3. Explicit user allow
		"allow explicit user allow only": {
			tknCtx: mkTknCtx("allowed_usr_1"),
		},
		"allow explicit user allow with unrelated groups": {
			tknCtx: mkTknCtx("allowed_usr_2", "unknown_grp_1", "unknown_grp_2"),
		},

		// 4. Group allow
		"allow group allow only": {
			tknCtx: mkTknCtx("unknown_usr", "allowed_grp_1"),
		},
		"allow group allow among unrelated groups": {
			tknCtx: mkTknCtx("unknown_usr", "unknown_grp_1", "allowed_grp_2", "unknown_grp_2"),
		},

		// 5. Deny by default
		"deny by default when no matches": {
			tknCtx:        mkTknCtx("unknown_usr", "unknown_grp_1", "unknown_grp_2"),
			errorContains: "deny by default",
		},
		"deny by default when username and groups empty": {
			tknCtx:        mkTknCtx(""),
			errorContains: "deny by default",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := authCtls.enforce(tt.tknCtx)

			if tt.errorContains == "" {
				assert.Nil(t, err)
			} else {
				assert.ErrorContains(t, err, tt.errorContains)
			}
		})
	}
}
