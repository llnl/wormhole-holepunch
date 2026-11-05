package oauthmngr

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/wazero"
)

func Test_wasmImports(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "oauthmngr.wasm")
	cmd := exec.CommandContext(ctx, "go", "build", "-buildmode=c-shared", "-o", path, "../../../cmd/plugins/oauthmngr")
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm", "CGO_ENABLED=0")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", output)

	code, err := os.ReadFile(path)
	require.NoError(t, err)
	runtime := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigInterpreter())
	defer runtime.Close(ctx)
	module, err := runtime.CompileModule(ctx, code)
	require.NoError(t, err)

	allowedWASI := []string{
		"sched_yield", "proc_exit", "args_get", "args_sizes_get", "clock_time_get",
		"environ_get", "environ_sizes_get", "fd_write", "random_get", "poll_oneoff",
		"fd_close", "fd_read", "fd_fdstat_get", "fd_fdstat_set_flags",
		"fd_prestat_get", "fd_prestat_dir_name",
	}
	for _, function := range module.ImportedFunctions() {
		namespace, name, _ := function.Import()
		if namespace == "wasi_snapshot_preview1" {
			assert.Contains(t, allowedWASI, name,
				"WASI import %s.%s has not been verified in Envoy proxy-wasm", namespace, name)
		} else {
			assert.Equal(t, "env", namespace, "unexpected import namespace for %s", name)
		}
	}
}
