package envoy

import (
	"testing"

	mutation_rules "github.com/envoyproxy/go-control-plane/envoy/config/common/mutation_rules/v3"
	"github.com/stretchr/testify/assert"

	"github.com/llnl/wormhole-holepunch/internal/args"
)

func Test_establishDefaultRequestHeaders(t *testing.T) {
	t.Run("subtoken header", func(t *testing.T) {
		got := establishDefaultRequestHeaders(args.TokenService{
			SubtokenHeader: "x-wormhole-subtoken",
		})

		assert.Contains(t, got, &mutation_rules.HeaderMutation{
			Action: &mutation_rules.HeaderMutation_Remove{
				Remove: "x-wormhole-subtoken",
			},
		})
	})
}
