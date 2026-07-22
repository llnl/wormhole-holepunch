package token

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
	"github.com/llnl/wormhole-holepunch/test/mocks/mock_requests"
)

func Test_internal_callProxyAuth(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	oauth2AuthURL, _ := url.Parse("http://example.com/oauth2/auth")
	oauth2RedirectURL, _ := url.Parse("http://example.com/oauth2/start")

	t.Run("redirect", func(t *testing.T) {
		client := mock_requests.NewMockClient(ctrl)
		client.EXPECT().GetHeaders(
			gomock.Any(),
			oauth2AuthURL.String(),
			gomock.Any(),
			gomock.Any(),
		).Return(
			map[string]string{},
			&requests.RequestFailedError{},
		)
		i := internal{
			client:            client,
			ll:                logs.InitializeDiscard(),
			oauth2AuthURL:     oauth2AuthURL,
			oauth2RedirectURL: oauth2RedirectURL,
		}

		_, err := i.callProxyAuth(
			t.Context(),
			requests.RequestDetails{
				Path:   "/foo",
				Scheme: "http",
				Host:   "example.com",
			},
			nil,
		)

		assert.NotNil(t, err)
		if err != nil {
			redirect, _ := err.RedirectRequired()
			assert.True(t, redirect)
		}
	})

	t.Run("missing header", func(t *testing.T) {
		client := mock_requests.NewMockClient(ctrl)
		client.EXPECT().GetHeaders(
			gomock.Any(),
			oauth2AuthURL.String(),
			gomock.Any(),
			gomock.Any(),
		).Return(
			map[string]string{
				keys.Oauth2ProxyAccessTokenHeader + "-New": "access.token.example",
			},
			nil,
		)
		i := internal{
			client:            client,
			ll:                logs.InitializeDiscard(),
			oauth2AuthURL:     oauth2AuthURL,
			oauth2RedirectURL: oauth2RedirectURL,
		}

		_, err := i.callProxyAuth(
			t.Context(),
			requests.RequestDetails{
				Path:   "/foo",
				Scheme: "http",
				Host:   "example.com",
			},
			nil,
		)

		assert.NotNil(t, err)
		if err != nil {
			assert.Contains(t, err.Error(), "Internal Server Error")
		}
	})

	t.Run("successful request", func(t *testing.T) {
		client := mock_requests.NewMockClient(ctrl)
		client.EXPECT().GetHeaders(
			gomock.Any(),
			oauth2AuthURL.String(),
			gomock.Any(),
			gomock.Any(),
		).Return(
			map[string]string{
				keys.Oauth2ProxyAccessTokenHeader: "access.token.example",
			},
			nil,
		)
		i := internal{
			client:            client,
			ll:                logs.InitializeDiscard(),
			oauth2AuthURL:     oauth2AuthURL,
			oauth2RedirectURL: oauth2RedirectURL,
		}

		res, err := i.callProxyAuth(
			t.Context(),
			requests.RequestDetails{
				Path:   "/foo",
				Scheme: "http",
				Host:   "example.com",
			},
			nil,
		)

		assert.Nil(t, err)
		assert.Equal(t, "access.token.example", res.headers[keys.Oauth2ProxyAccessTokenHeader])
	})
}

func Test_internal_constructProxyRedirect(t *testing.T) {
	t.Run("adds redirect param and preserves existing query", func(t *testing.T) {
		base, err := url.Parse("https://auth.example.com/oauth2/start?client_id=abc")
		assert.NoError(t, err)

		i := internal{
			oauth2RedirectURL: base,
		}

		req := requests.RequestDetails{
			Scheme: "https",
			Host:   "app.example.com",
			Path:   "/callback",
		}

		got := i.constructProxyRedirect(req)

		parsed, err := url.Parse(got)
		assert.NoError(t, err)

		assert.Equal(t, "https", parsed.Scheme)
		assert.Equal(t, "auth.example.com", parsed.Host)
		assert.Equal(t, "/oauth2/start", parsed.Path)

		q := parsed.Query()
		assert.Equal(t, "abc", q.Get("client_id"))

		wantTarget := "https://app.example.com/callback"
		assert.Equal(t, wantTarget, q.Get(redirectParam))
	})

	t.Run("does not mutate internal base URL", func(t *testing.T) {
		base, err := url.Parse("https://auth.example.com/oauth2/start")
		assert.NoError(t, err)

		i := internal{
			oauth2RedirectURL: base,
		}

		orig := base.String()

		req := requests.RequestDetails{
			Scheme: "https",
			Host:   "app.example.com",
			Path:   "/callback",
		}

		_ = i.constructProxyRedirect(req)

		assert.Equal(t, orig, base.String())
	})

	t.Run("encodes special characters in redirect value (round-trips via Query().Get)", func(t *testing.T) {
		base, err := url.Parse("https://auth.example.com/oauth2/start")
		assert.NoError(t, err)

		i := internal{
			oauth2RedirectURL: base,
		}

		req := requests.RequestDetails{
			Scheme: "https",
			Host:   "app.example.com",
			Path:   "/path with space",
		}

		got := i.constructProxyRedirect(req)

		parsed, err := url.Parse(got)
		assert.NoError(t, err)

		// Query().Get returns the decoded value.
		wantTarget := "https://app.example.com/path%20with%20space"
		assert.Equal(t, wantTarget, parsed.Query().Get(redirectParam))

		assert.NotEmpty(t, parsed.RawQuery)
	})

	t.Run("overwrites redirect param when already present", func(t *testing.T) {
		// This assumes constructRedirect uses q.Set (not q.Add).
		base, err := url.Parse("https://auth.example.com/oauth2/start?redirect=old")
		assert.NoError(t, err)

		i := internal{
			oauth2RedirectURL: base,
		}

		req := requests.RequestDetails{
			Scheme: "https",
			Host:   "app.example.com",
			Path:   "/callback",
		}

		got := i.constructProxyRedirect(req)

		parsed, err := url.Parse(got)
		assert.NoError(t, err)

		wantTarget := "https://app.example.com/callback"
		assert.Equal(t, wantTarget, parsed.Query().Get(redirectParam))
	})
}
