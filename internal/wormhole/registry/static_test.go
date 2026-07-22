package registry

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
)

func Test_loadStaticFile(t *testing.T) {
	t.Run("no file", func(t *testing.T) {
		got, err := loadStaticFile(logs.InitializeDiscard(), "")

		assert.NoError(t, err)
		assert.Len(t, got, 0)
	})

	t.Run("invalid yaml", func(t *testing.T) {
		filename := t.TempDir() + "/invalid.yaml"
		os.WriteFile(filename, []byte("-1"), 0700)

		_, err := loadStaticFile(logs.InitializeDiscard(), filename)

		assert.Error(t, err)
	})

	t.Run("test data", func(t *testing.T) {
		got, err := loadStaticFile(logs.InitializeDiscard(), "../../../test/data/static.yaml")

		assert.NoError(t, err)
		assert.Len(t, got, 2)
	})
}
