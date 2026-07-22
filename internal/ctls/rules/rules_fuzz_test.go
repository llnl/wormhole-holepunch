package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/llnl/wormhole-holepunch/test/tools"
)

func runFuzzTest(f *testing.F, tag string) {
	for _, v := range tools.UnencodedFuzzStr() {
		f.Add(v)
	}

	f.Fuzz(func(t *testing.T, substring string) {
		v := NewValidator()
		err := v.Var(substring, tag)
		assert.Error(t, err, substring)
	})
}

//

func Fuzz_checkDirectory(f *testing.F) {
	runFuzzTest(f, "reqToken")
}

func Fuzz_checkAuthToken(f *testing.F) {
	runFuzzTest(f, "kid")
}
