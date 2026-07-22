package args

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/urfave/cli/v3"
)

const (
	envPrefix = "HOLEPUNCH_"
)

type FlagBuilder struct {
	Flags []cli.Flag
}

func NewBuilder() *FlagBuilder {
	return &FlagBuilder{
		Flags: make([]cli.Flag, 0),
	}
}

func (f *FlagBuilder) Generic(add []cli.Flag) *FlagBuilder {
	f.Flags = append(f.Flags, add...)
	return f
}

// GetValueOrFile returns the value for a flag/arg name from ctx.
// If the value can be read as a file path, it returns the file contents.
// Otherwise it returns the raw value.
func GetValueOrFile(proposedValue string) string {
	v := strings.TrimSpace(proposedValue)
	if v == "" {
		return ""
	}

	if b, err := os.ReadFile(filepath.Clean(v)); err == nil {
		return strings.TrimSpace(string(b))
	}

	return v
}

//

func envWrapper(varName any) cli.ValueSourceChain {
	switch v := varName.(type) {
	case string:
		return cli.EnvVars(envPrefix + v)
	case []string:
		var prefixedStrings []string
		for _, str := range v {
			prefixedStrings = append(prefixedStrings, envPrefix+str)
		}

		return cli.EnvVars(prefixedStrings...)
	default:
		return cli.ValueSourceChain{}
	}
}

func validateURLAction(_ context.Context, cCmd *cli.Command, s string) error {
	_, err := url.Parse(s)
	if err != nil {
		return errors.New("invalid URL " + s)
	}

	return nil
}
