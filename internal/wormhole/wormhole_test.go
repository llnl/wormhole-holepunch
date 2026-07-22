package wormhole

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_FloatTime_UnmarshalJSON(t *testing.T) {
	tests := map[string]struct {
		inputJSON   string
		expected    time.Time
		expectError bool
	}{
		"Regular timestamp with fractional seconds": {
			inputJSON: `1771646758.731226`,
			expected:  time.Unix(1771646758, 731226000),
		},
		"Regular timestamp without fractional part": {
			inputJSON: `1771646758.0`,
			expected:  time.Unix(1771646758, 0),
		},
		"Zero timestamp": {
			inputJSON: `0.0`,
			expected:  time.Unix(0, 0),
		},
		"Invalid JSON input": {
			inputJSON:   `"invalid"`,
			expectError: true,
		},
		"Empty JSON input": {
			inputJSON:   ``,
			expectError: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var ft FloatTime

			err := json.Unmarshal([]byte(tt.inputJSON), &ft)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if !tt.expected.IsZero() {
				assert.Equal(t, tt.expected.Unix(), ft.Unix())
			}
		})
	}
}

func Test_FloatTime_MarshalJSON(t *testing.T) {
	tests := map[string]struct {
		inputTime time.Time
		expected  string
	}{
		"Regular time with fractional seconds": {
			inputTime: time.Unix(1771646758, 731226000),
			expected:  `1771646758.731226`,
		},
		"Regular time without fractional part": {
			inputTime: time.Unix(1771646758, 0),
			expected:  `1771646758`,
		},
		"Time at epoch": {
			inputTime: time.Unix(0, 0),
			expected:  `0`,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ft := FloatTime{Time: tt.inputTime}

			data, err := ft.MarshalJSON()

			assert.NoError(t, err)
			assert.Equal(t, tt.expected, string(data))
		})
	}
}

func Test_FloatTime_RoundTrip(t *testing.T) {
	// Test marshalling and unmarshalling to ensure the value remains consistent
	originalTime := time.Unix(1771646758, 731226000)
	ft := FloatTime{Time: originalTime}

	data, err := ft.MarshalJSON()
	if err != nil {
		assert.NoError(t, err, "MarshalJSON")
		t.FailNow()
	}

	var unmarshalledFT FloatTime
	if err := json.Unmarshal(data, &unmarshalledFT); err != nil {
		assert.NoError(t, err, "Unmarshal")
		t.FailNow()
	}

	// Compare original and unmarshalled value
	assert.Equal(t, originalTime.Unix(), unmarshalledFT.Unix())
}
