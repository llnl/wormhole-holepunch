package registry

import (
	"os"
	"path/filepath"

	"sigs.k8s.io/yaml"

	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/wormhole"
)

type StaticSource struct {
	Sources []wormhole.RawSource `yaml:"sources"`
}

// loadStaticFile parses a proposed static mappings files, decoding any
// identified sources into the slice. Overlapping sources with the Router
// Registry are the responsibility of the Holepunch admin to plan for.
func loadStaticFile(ll logs.Logger, filename string) ([]wormhole.RawSource, error) {
	if filename == "" {
		return []wormhole.RawSource{}, nil
	}

	b, err := os.ReadFile(filepath.Clean(filename))
	if err != nil {
		return []wormhole.RawSource{}, err
	}

	static := StaticSource{}

	err = yaml.Unmarshal(b, &static)
	if err != nil {
		return nil, err
	}

	ll.Info("static configurations found in: " + filename)

	return static.Sources, nil
}
