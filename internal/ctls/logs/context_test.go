package logs

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_FromContext(t *testing.T) {
	t.Run("returns stored logger", func(t *testing.T) {
		ll := InitializeDiscard()
		ctx := NewContext(context.Background(), ll)

		assert.Equal(t, ll, FromContext(ctx, nil))
		assert.Equal(t, ll, MustFromContext(ctx))
	})

	t.Run("returns fallback when absent", func(t *testing.T) {
		fallback := InitializeDiscard()

		assert.Equal(t, fallback, FromContext(context.Background(), fallback))
	})

	t.Run("must panics when absent", func(t *testing.T) {
		assert.Panics(t, func() { MustFromContext(context.Background()) })
	})
}
