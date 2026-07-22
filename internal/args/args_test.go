package args

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli/v3"
)

func Test_NewBuilder(t *testing.T) {
	b := NewBuilder()

	assert.NotNil(t, b)
	assert.NotNil(t, b.Flags)
	assert.Len(t, b.Flags, 0)
}

func Test_FlagBuilder_Generic(t *testing.T) {
	b := NewBuilder()

	f1 := &cli.StringFlag{Name: "a"}
	f2 := &cli.StringFlag{Name: "b"}

	// appends and returns same builder
	ret := b.Generic([]cli.Flag{f1, f2})
	assert.Same(t, b, ret)
	assert.Len(t, b.Flags, 2)
	assert.Same(t, f1, b.Flags[0])
	assert.Same(t, f2, b.Flags[1])

	// appends again
	f3 := &cli.StringFlag{Name: "c"}
	b.Generic([]cli.Flag{f3})
	assert.Len(t, b.Flags, 3)
	assert.Same(t, f3, b.Flags[2])
}

func Test_GetValueOrFile(t *testing.T) {
	t.Run("EmptyReturnsEmpty", func(t *testing.T) {
		assert.Equal(t, "", GetValueOrFile(""))
		assert.Equal(t, "", GetValueOrFile("   "))
	})

	t.Run("NonFileReturnsTrimmedValue", func(t *testing.T) {
		assert.Equal(t, "abc", GetValueOrFile(" abc "))
	})

	t.Run("ExistingFileReturnsTrimmedContents", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "key.txt")

		err := os.WriteFile(p, []byte("  secret-key \n"), 0o600)
		assert.NoError(t, err)

		// provide path with surrounding whitespace; should read file + trim contents
		got := GetValueOrFile("  " + p + "  ")
		assert.Equal(t, "secret-key", got)
	})

	t.Run("UnreadableOrMissingFileFallsBackToValue", func(t *testing.T) {
		// very likely doesn't exist; function should just return the proposed value (trimmed)
		missing := filepath.Join(t.TempDir(), "does-not-exist.txt")
		assert.Equal(t, missing, GetValueOrFile(" "+missing+" "))
	})
}

func Test_EnvWrapper(t *testing.T) {
	t.Parallel()

	t.Run("string", func(t *testing.T) {
		vs := envWrapper("FOO")

		os.Unsetenv(envPrefix + "FOO")
		if _, ok := vs.Lookup(); ok {
			t.Fatalf("expected no value when %q is unset", envPrefix+"FOO")
		}

		want := "bar"
		os.Setenv(envPrefix+"FOO", want)
		t.Cleanup(func() { os.Unsetenv(envPrefix + "FOO") })

		got, ok := vs.Lookup()
		assert.True(t, ok)
		assert.Equal(t, want, got)
	})

	t.Run("slice", func(t *testing.T) {
		vs := envWrapper([]string{"A", "B"})

		os.Unsetenv(envPrefix + "A")
		os.Unsetenv(envPrefix + "B")
		if _, ok := vs.Lookup(); ok {
			t.Fatalf("expected no value when %q and %q are unset", envPrefix+"A", envPrefix+"B")
		}

		want := "v2"
		os.Setenv(envPrefix+"B", want)
		t.Cleanup(func() { os.Unsetenv(envPrefix + "B") })

		got, ok := vs.Lookup()
		assert.True(t, ok)
		assert.Equal(t, want, got)
	})

	t.Run("unsupported", func(t *testing.T) {
		vs := envWrapper(123)

		// ValueSourceChain{} should never resolve to a value.
		if _, ok := vs.Lookup(); ok {
			t.Fatalf("expected no value for unsupported type")
		}
	})
}

func Test_ValidateURLAction(t *testing.T) {
	var cmd cli.Command

	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"valid_http", "https://example.com/path?q=1", false},
		{"valid_host_only", "example.com", false}, // url.Parse accepts this as a path
		{"invalid_control_char", "http://exa mple.com", true},
		{"invalid_escape", "http://example.com/%zz", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateURLAction(context.Background(), &cmd, tt.in)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
