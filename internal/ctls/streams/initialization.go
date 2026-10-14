package streams

import (
	"context"
	"errors"
	"time"

	"github.com/nats-io/nats.go"
)

// initializeWithRetry lets resource setup survive transient NATS startup failures.
// Each attempt uses the caller's context, so expired deadlines are never renewed.
func initializeWithRetry[T any](ctx context.Context, c *Client, initialize func() (T, error)) (T, error) {
	var zero T

	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return zero, err
		}

		value, err := initialize()
		if err == nil {
			return value, nil
		}

		if ctx.Err() != nil {
			return zero, ctx.Err()
		}

		if attempt >= maxRetries || !transientInitializationError(err) {
			return zero, err
		}

		c.ll.Warnf("NATS initialization failed; retrying in %s (%d/%d): %v",
			waitBetween, attempt+1, maxRetries, err)

		timer := time.NewTimer(waitBetween)
		select {
		case <-ctx.Done():
			timer.Stop()
			return zero, ctx.Err()
		case <-timer.C:
		}
	}
}

func transientInitializationError(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, nats.ErrTimeout) ||
		errors.Is(err, nats.ErrNoResponders) ||
		errors.Is(err, nats.ErrDisconnected)
}
