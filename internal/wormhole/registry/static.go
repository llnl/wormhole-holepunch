package registry

import (
	"os"
	"path/filepath"

	"sigs.k8s.io/yaml"

	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
)

type StaticSource struct {
	Sources []staticRawSource `json:"sources" yaml:"sources"`
}

// staticRawSource extends the RawSource with admin only configurations that are
// only available in the static file. Since sigs.k8s.io/yaml decodes via the json
// tags, these fields cannot live directly on the RawSource without also exposing
// them to the route registry.
type staticRawSource struct {
	RawSource

	NoAuth bool `json:"no_auth" yaml:"no_auth"`
}

// loadStaticFile parses a proposed static mappings files, decoding any
// identified sources into the slice. Overlapping sources with the Router
// Registry are the responsibility of the Holepunch admin to plan for.
func loadStaticFile(ll logs.Logger, filename string) ([]RawSource, error) {
	if filename == "" {
		return []RawSource{}, nil
	}

	b, err := os.ReadFile(filepath.Clean(filename))
	if err != nil {
		return []RawSource{}, err
	}

	static := StaticSource{}

	err = yaml.Unmarshal(b, &static)
	if err != nil {
		return nil, err
	}

	ll.Info("static configurations found in: " + filename)

	sources := make([]RawSource, 0, len(static.Sources))

	for _, s := range static.Sources {
		rs := s.RawSource
		rs.NoAuth = s.NoAuth

		if rs.NoAuth {
			ll.Warn("authorization disabled for static source: " + rs.ID)
		}

		sources = append(sources, rs)
	}

	return sources, nil
}
