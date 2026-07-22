package envoy

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func Test_normalizeName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Short valid string - no sanitization required",
			input:    "valid_name-123",
			expected: "valid_name-123",
		},
		{
			name:     "String with invalid characters - sanitization required",
			input:    "invalid!@#chars<>?",
			expected: "invalidchars",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "String with only invalid characters",
			input:    "!@#$%^&*()<>?",
			expected: "",
		},
		{
			name:  "String longer than 127 characters",
			input: strings.Repeat("a", 128),
			expected: func() string {
				hash := sha256.Sum256([]byte(strings.Repeat("a", 128)))
				return hex.EncodeToString(hash[:])
			}(),
		},
		{
			name:     "String exactly 127 characters - no hashing required",
			input:    strings.Repeat("a", 127),
			expected: strings.Repeat("a", 127),
		},
		{
			name:     "String with mixed valid and invalid characters",
			input:    "partially!valid<>string",
			expected: "partiallyvalidstring",
		},
		{
			name:     "String with underscore, hyphen, and dot",
			input:    "valid.string_name-123",
			expected: "valid.string_name-123",
		},
		{
			name:     "String containing spaces",
			input:    "name with spaces",
			expected: "namewithspaces",
		},
		{
			name:     "String containing numbers only",
			input:    "1234567890",
			expected: "1234567890",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeName(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeName(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}
