package logs

import (
	"log/slog"
	"testing"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/stretchr/testify/assert"
)

func Test_Initialize(t *testing.T) {
	type fields struct {
		Disable  bool
		Level    string
		Location string
		Network  string
		Address  string
	}
	tests := map[string]struct {
		name   string
		fields fields
		assert func(*testing.T, Logger, error)
	}{
		"invalid syslog address": {
			fields: fields{
				Location: "syslog",
				Network:  "invalid",
				Address:  "invalid-address",
			},
			assert: func(t *testing.T, _ Logger, err error) {
				assert.Error(t, err)
			},
		},
		"disable": {
			fields: fields{
				Disable:  true,
				Location: "syslog",
				Network:  "invalid",
				Address:  "invalid-address",
			},
			assert: func(t *testing.T, ll Logger, err error) {
				assert.NoError(t, err)
				ll.Info("this log message should be discarded")
			},
		},
		"stdout - default": {
			fields: fields{
				Location: "stdout",
			},
			assert: func(t *testing.T, ll Logger, err error) {
				assert.NoError(t, err)

				ll.With([]slog.Attr{slog.String("hello", "world!")})
				ll.Info(
					"info stdout",
					ll.IntArg("int", 1),
					ll.StringArg("string", "value"),
				)

				ll.Debug("debug stdout")
				ll.Warn("warn stdout")
				ll.Error("error stdout")

				ll.Infof("formant %s", "info")
				ll.Debugf("formant %s", "debug")
				ll.Warnf("formant %s", "warn")
				ll.Errorf("formant %s", "error")
			},
		},
		"stderr - warn": {
			fields: fields{
				Level:    "warn",
				Location: "stderr",
			},
			assert: func(t *testing.T, ll Logger, err error) {
				assert.NoError(t, err)
				ll.Warn("info stderr")
			},
		},
		"write to file": {
			fields: fields{
				Level:    "info",
				Location: t.TempDir() + "/test.log",
			},
			assert: func(t *testing.T, ll Logger, err error) {
				assert.NoError(t, err)
				ll.Info("info file")
			},
		},
		"stderr - ctx": {
			fields: fields{
				Level:    "debug",
				Location: "stderr",
			},
			assert: func(t *testing.T, ll Logger, err error) {
				assert.NoError(t, err)

				ll.DebugCtx(t.Context(), "debug context")
				ll.InfoCtx(t.Context(), "info context")
				ll.WarnCtx(t.Context(), "warn context")
				ll.ErrorCtx(t.Context(), "error context")
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			loggingArgs := args.Logging{
				LoggingDisable:  tt.fields.Disable,
				LoggingLevel:    tt.fields.Level,
				LoggingLocation: tt.fields.Location,
				LoggingNetwork:  tt.fields.Network,
				LoggingAddress:  tt.fields.Address,
			}

			got, err := Initialize(loggingArgs)

			tt.assert(t, got, err)
		})
	}
}

func Test_InitializeDiscard(t *testing.T) {
	ll := InitializeDiscard()
	ll.Info("this log message should be discarded")
}

func Test_InitializeStderr(t *testing.T) {
	ll := InitializeStderr()
	ll.Info("this log message should be stderr")
}
