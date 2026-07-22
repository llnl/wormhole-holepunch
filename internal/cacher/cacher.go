package cacher

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/wormhole/registry"
	"github.com/llnl/wormhole-holepunch/internal/wormhole/token"
)

const (
	// failureWindow allowed timeframe failures will be tracked.
	failureWindow = time.Hour
)

// StartService initializes all cache sources then manages the necessary
// routines to ensures caching is accomplished.
func StartService(
	ctx context.Context,
	cacherArgs args.Cacher,
	ll logs.Logger,
	routeReg registry.Router,
	_ token.Authenticator,
) error {
	err := routeReg.PublishSources(ctx)
	if err != nil {
		return fmt.Errorf("failed to publish initial route source: %w", err)
	}

	var wg sync.WaitGroup
	wg.Add(1) // Expand this once we fully support token cache management.

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return manageRoutes(ctx, cacherArgs, ll, routeReg) })

	return g.Wait()
}

//

func manageRoutes(
	ctx context.Context,
	cacherArgs args.Cacher,
	ll logs.Logger,
	routeReg registry.Router,
) error {
	ticker := time.NewTicker(cacherArgs.RouteRefresh)
	defer ticker.Stop()

	var failures []time.Time

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			err := routeReg.PublishSources(ctx)
			if err != nil {
				err = fmt.Errorf("failed to publish updated route source: %w", err)
				failures = appendFailure(failures)

				ll.ErrorCtx(ctx, err.Error())

				if len(failures) >= cacherArgs.MaxFailures {
					ll.ErrorCtx(
						ctx,
						fmt.Sprintf("maximum failures reached: %s", failures),
					)

					return err
				}
			}
		}
	}
}

func appendFailure(failures []time.Time) []time.Time {
	now := time.Now()
	failures = append(failures, now)
	cutoff := now.Add(-failureWindow)

	// Drop all entries < cutoff
	i := 0
	for i < len(failures) && failures[i].Before(cutoff) {
		i++
	}

	return failures[i:]
}
