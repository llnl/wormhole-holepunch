package envoy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"net/url"
	"regexp"

	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"

	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
)

const (
	routeName = "local_route"
)

var allowedPattern = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

// initSnapshot updates the cache for the first time in a deployment, any errors should
// cause the startup to fail.
func (s *xdsServer) initSnapshot(ctx context.Context) error {
	s.ll.Info("initializing snapshot")

	snapshot, err := s.generateSnapshot(ctx)
	if err != nil {
		return err
	}

	s.ll.Debugf("initial snapshot %+v", snapshot)

	return nil
}

// refreshSnapshot updates the cache, any errors are simply logged.
func (s *xdsServer) refreshSnapshot(ctx context.Context) {
	s.ll.Debug("refreshing snapshot")

	_, _ = s.generateSnapshot(ctx)
}

// generateSnapshot parses the currently cached proxy controls to create a new snapshot
// of potential Envoy resources. Though the snapshot itself is returned, it is also
// saved to the previously configured cache during this process.
func (s *xdsServer) generateSnapshot(ctx context.Context) (*cache.Snapshot, error) {
	ctls := s.routeReg.FetchProxyControls()

	version := computeChecksum(ctls)

	resources := map[resource.Type][]types.Resource{
		resource.ClusterType:  s.makeClusters(ctls),
		resource.RouteType:    {s.makeRoutes(routeName, ctls)},
		resource.ListenerType: {s.makeHTTPListener(s.listenerName(), routeName)},
	}

	snap, err := cache.NewSnapshot(
		version,
		resources,
	)
	if err != nil {
		s.ll.Errorf("failed to create snapshot: %s", err.Error())
		return nil, err
	}

	if err = snap.Consistent(); err != nil {
		s.ll.Errorf("snapshot inconsistent: %s", err.Error())
		return nil, err
	}

	if err = s.cache.SetSnapshot(ctx, s.xdsArgs.NodeName, snap); err != nil {
		s.ll.Errorf("failed to set snapshot: %s", err.Error())
		return nil, err
	}

	s.ll.Debug("successfully established + saved snapshot: " + version)

	return snap, err
}

// listenerName generates a valid Envoy listener name based upon configurations.
func (s *xdsServer) listenerName() string {
	initial := fmt.Sprintf("wh_%s_%d", s.xdsArgs.ListenerAddress, s.xdsArgs.ListenerPort)
	return normalizeName(initial)
}

// clusterName generates a valid Envoy cluster name based on the provided URL.
func clusterName(dst *url.URL) string {
	initial := fmt.Sprintf("wh_%s_%d", dst.Hostname(), requests.IdentifyPort(dst))
	return normalizeName(initial)
}

// computeChecksum generates a checksum for a given interface to assist in providing
// a unique name for the snapshot. Users influenced structured are not utilized as
// part of this checksum so we do not worry about the risk of conflicts.
func computeChecksum(data any) string {
	var buffer bytes.Buffer

	encoder := gob.NewEncoder(&buffer)

	if err := encoder.Encode(data); err != nil {
		// Since we tightly control the check
		return "unknown"
	}

	return fmt.Sprintf("%08x", crc32.ChecksumIEEE(buffer.Bytes()))
}

// normalizeName ensures the propose name/key can be used for Envoy configs.
//   - If length is greater than 127, fall back to sha256 checksum
//   - Otherwise, it parses and sanitizes the string
func normalizeName(s string) string {
	// If the string length is greater than 127, return the sha256 checksum
	if len(s) > 127 {
		hash := sha256.Sum256([]byte(s))
		return hex.EncodeToString(hash[:])
	}

	// Otherwise, sanitize the string
	return allowedPattern.ReplaceAllString(s, "")
}
