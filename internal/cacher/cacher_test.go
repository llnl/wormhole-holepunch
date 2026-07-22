package cacher

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/test/mocks/mock_registry"
	"github.com/llnl/wormhole-holepunch/test/mocks/mock_token"
)

func Test_StartService(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ll := logs.InitializeDiscard()

	t.Run("functional requests", func(t *testing.T) {
		routeReg := mock_registry.NewMockRouter(ctrl)
		routeReg.EXPECT().PublishSources(gomock.Any()).Return(nil).AnyTimes()

		tokenAuth := mock_token.NewMockAuthenticator(ctrl)

		cacherArgs := args.Cacher{
			RouteRefresh: time.Second,
		}

		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()

		err := StartService(ctx, cacherArgs, ll, routeReg, tokenAuth)

		assert.NoError(t, err)
	})

	t.Run("failed initial registry ", func(t *testing.T) {
		routeReg := mock_registry.NewMockRouter(ctrl)
		routeReg.EXPECT().PublishSources(gomock.Any()).Return(errors.New("failed request"))

		tokenAuth := mock_token.NewMockAuthenticator(ctrl)

		cacherArgs := args.Cacher{
			RouteRefresh: time.Second,
		}

		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()

		err := StartService(ctx, cacherArgs, ll, routeReg, tokenAuth)

		assert.Error(t, err)
	})

	t.Run("registry max failures", func(t *testing.T) {
		routeReg := mock_registry.NewMockRouter(ctrl)
		routeReg.EXPECT().PublishSources(gomock.Any()).Return(nil)
		routeReg.EXPECT().PublishSources(gomock.Any()).Return(errors.New("failed request")).AnyTimes()

		tokenAuth := mock_token.NewMockAuthenticator(ctrl)

		cacherArgs := args.Cacher{
			MaxFailures:  1,
			RouteRefresh: time.Second,
		}

		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()

		err := StartService(ctx, cacherArgs, ll, routeReg, tokenAuth)

		assert.Error(t, err)
	})
}

func Test_appendFailure(t *testing.T) {
	t.Parallel()

	t.Run("empty input", func(t *testing.T) {
		start := time.Now()
		out := appendFailure(nil)
		end := time.Now()

		assert.Len(t, out, 1)
		assert.True(t, out[0].After(start))
		assert.True(t, out[0].Before(end))
	})

	t.Run("appends now and drops old", func(t *testing.T) {
		// Make a slice where some entries are older than the cutoff, and some are newer.
		before := time.Now()
		cutoff := before.Add(-failureWindow)

		in := []time.Time{
			cutoff.Add(-42 * time.Second),
			cutoff.Add(-1 * time.Nanosecond),
			cutoff.Add(42 * time.Second),
			cutoff.Add(10 * time.Millisecond),
		}

		start := time.Now()
		out := appendFailure(in)
		end := time.Now()

		assert.Len(t, out, 3)
		assert.True(t, out[len(out)-1].After(start))
		assert.True(t, out[len(out)-1].Before(end))
	})

	t.Run("all old are dropped", func(t *testing.T) {
		before := time.Now()
		cutoff := before.Add(-failureWindow)

		in := []time.Time{
			cutoff.Add(-5 * time.Second),
			cutoff.Add(-1 * time.Millisecond),
		}

		out := appendFailure(in)

		assert.Len(t, out, 1)
	})
}
