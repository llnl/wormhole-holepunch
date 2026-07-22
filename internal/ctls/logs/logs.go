package logs

import (
	"context"
	"io"
	"log/slog"
	"log/syslog"
	"os"
	"path/filepath"
	"strings"

	"go.opentelemetry.io/otel/attribute"

	"github.com/llnl/wormhole-holepunch/internal/args"
)

const (
	defaultLevel = slog.LevelInfo
	loggerTag    = "holepunch"
)

// Logger serves two purposes, first and foremost it offers a mechanism by which we
// can log actions with expandable context. It also realizes a valid log.Logger interface
// (https://pkg.go.dev/github.com/envoyproxy/go-control-plane@v0.13.4/pkg/log#Logger)
// for the Envoy go-control-plane.
type Logger interface {
	// DebugCtx logs the messages at a DEBUG level, if an OTEL span can be retrieved
	// from the context the message is also added as an event.
	DebugCtx(ctx context.Context, msg string, attr ...slog.Attr)
	// InfoCtx logs the messages at a INFO level, if an OTEL span can be retrieved
	// from the context the message is also added as an event.
	InfoCtx(ctx context.Context, msg string, attr ...slog.Attr)
	// WarnCtx logs the messages at a WARN level, if an OTEL span can be retrieved
	// from the context the message is also added as an event.
	WarnCtx(ctx context.Context, msg string, attr ...slog.Attr)
	// ErrorCtx logs the messages at a ERROR level, if an OTEL span can be retrieved
	// from the context the message is also added as an event.
	ErrorCtx(ctx context.Context, msg string, attr ...slog.Attr)

	StartSpan(ctx context.Context, name string) (context.Context, func())

	Debug(msg string, attr ...slog.Attr)
	Info(msg string, attr ...slog.Attr)
	Warn(msg string, attr ...slog.Attr)
	Error(msg string, attr ...slog.Attr)

	StringArg(k, v string) slog.Attr
	IntArg(k string, v int) slog.Attr
	With(attrs []slog.Attr) Logger

	/*
		Functions for Envoy interface compatibility...
	*/

	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

func Initialize(loggingArgs args.Logging) (Logger, error) {
	hOpts := &slog.HandlerOptions{Level: level(loggingArgs.LoggingLevel)}
	if loggingArgs.LoggingDisable {
		return logger{
			s: slog.New(slog.DiscardHandler),
		}, nil
	}

	w, err := writer(loggingArgs)
	if err != nil {
		return nil, err
	}

	fields := fields()

	return logger{
		s:         slog.New(slog.NewJSONHandler(w, hOpts).WithAttrs(fields)),
		spanAttrs: make([]attribute.KeyValue, 0),
	}, nil
}

// InitializeDiscard creates a logger that discards all log messages.
func InitializeDiscard() Logger {
	return logger{
		s:         slog.New(slog.DiscardHandler),
		spanAttrs: make([]attribute.KeyValue, 0),
	}
}

// InitializeStderr creates a logger that prints all logs to Stderr.
func InitializeStderr() logger {
	hOpts := &slog.HandlerOptions{Level: defaultLevel}
	fields := fields()

	return logger{
		s:         slog.New(slog.NewJSONHandler(os.Stderr, hOpts).WithAttrs(fields)),
		spanAttrs: make([]attribute.KeyValue, 0),
	}
}

//

func writer(loggingArgs args.Logging) (io.Writer, error) {
	switch strings.ToLower(loggingArgs.LoggingLocation) {
	case "syslog", "":
		if loggingArgs.LoggingAddress != "" {
			return syslog.Dial(
				loggingArgs.LoggingNetwork,
				loggingArgs.LoggingAddress,
				syslog.LOG_DEBUG,
				loggerTag,
			)
		}

		return syslog.New(syslog.LOG_DEBUG, loggerTag)
	case "stdout":
		return os.Stdout, nil
	case "stderr":
		return os.Stderr, nil
	}

	return LogFile{
		file: filepath.Clean(loggingArgs.LoggingLocation),
	}, nil
}

func level(lvl string) slog.Level {
	switch strings.ToLower(lvl) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return defaultLevel
	}
}

func fields() []slog.Attr {
	f := []slog.Attr{}

	host, err := os.Hostname()
	if err == nil {
		// Failure to identify hostname should not result in a job failure.
		f = append(f, slog.String("hostname", host))
	}

	return f
}
