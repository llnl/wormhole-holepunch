package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ValidateURL(t *testing.T) {
	tests := map[string]struct {
		str           string
		wantURL       string
		errorContains string
	}{
		"rejects header larger than maximum": {
			str:           makeIllegalStringLength(),
			errorContains: "proposed URL surpassed maximum header size",
		},
		"rejects malformed URL": {
			str:           "http://[::1",
			errorContains: "invalid URL:",
		},
		"rejects unsupported scheme": {
			str:           "ftp://8.8.8.8",
			errorContains: "unsupported URL scheme 'ftp': only http and https allowed",
		},
		"rejects missing hostname": {
			str:           "http:///path",
			errorContains: "URL must have a hostname",
		},
		"rejects blocked localhost pattern case insensitively": {
			str:           "http://LOCALHOST",
			errorContains: "matches blocked pattern 'localhost'",
		},
		"rejects blocked kubernetes hostname pattern": {
			str:           "http://api.kubernetes.default.svc",
			errorContains: "matches blocked pattern 'kubernetes.default'",
		},
		"rejects blocked internal hostname pattern": {
			str:           "http://service.internal",
			errorContains: "matches blocked pattern '.internal'",
		},
		"rejects loopback IPv4 address": {
			str:           "http://127.0.0.1",
			errorContains: "loopback addresses not allowed",
		},
		"rejects link local IPv4 address": {
			str:           "http://169.254.1.1",
			errorContains: "link-local addresses not allowed",
		},
		"rejects unspecified IPv4 address": {
			str:           "http://0.0.0.0",
			errorContains: "unspecified addresses not allowed",
		},
		"accepts valid public http URL": {
			str:     "http://8.8.8.8",
			wantURL: "http://8.8.8.8",
		},
		"accepts valid public https URL with path and query": {
			str:     "https://8.8.8.8/path?q=1",
			wantURL: "https://8.8.8.8/path?q=1",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := ValidateURL(tt.str, true)

			if tt.wantURL != "" {
				assert.NoError(t, err)
				assert.NotNil(t, got)
				assert.Equal(t, tt.wantURL, got.String())
			}

			if tt.errorContains == "" {
				assert.NoError(t, err)
			} else {
				assert.Nil(t, got)
				assert.ErrorContains(t, err, tt.errorContains)
			}
		})
	}
}
