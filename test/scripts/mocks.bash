#!/usr/bin/env bash

# Re-build all mock files (https://github.com/uber-go/mock)

set -eo pipefail
set -o xtrace

mockgen() {
    "$(go env GOPATH)/bin/mockgen" \
        -source="internal/$1" \
        -destination="test/mocks/$2" \
        -package="$3"
}

mockgen ctls/aescipher/aescipher.go mock_aescipher/mock_aescipher.go mock_aescipher
mockgen ctls/logs/logs.go mock_logs/mock_logs.go mock_logs
mockgen ctls/requests/requests.go mock_requests/mock_requests.go mock_requests
mockgen ctls/streams/pubsub.go mock_streams/mock_pubsub.go mock_streams
mockgen ctls/streams/kvstore.go mock_streams/mock_kvstore.go mock_streams
mockgen wormhole/registry/router.go mock_registry/mock_registry.go mock_registry
mockgen wormhole/token/token.go mock_token/mock_token.go mock_token
