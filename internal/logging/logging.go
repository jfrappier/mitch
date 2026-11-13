// Package logging sets up the one logger Mitch uses everywhere.
//
// Every log line has the same shape so it can be read by people and parsed by
// log tools without custom parsing:
//
//	time=2026-11-12T19:30:00.000-05:00 level=INFO msg="scan started" component=scan operation=list_mounts
//
// Two output formats are supported:
//
//   - "text" (default): key=value pairs from Go's slog.TextHandler.
//   - "json": one JSON object per line from Go's slog.JSONHandler.
//
// Both formats always include time, level and msg. Mitch code always adds
// component (which part of Mitch wrote the line) and operation (what it was
// doing). Lines about Vault calls also add http_status and duration_ms, and
// failures add error.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// Field names used on every log line. Use these constants instead of typing
// the names by hand, so every line uses exactly the same spelling.
const (
	FieldComponent  = "component"
	FieldOperation  = "operation"
	FieldHTTPStatus = "http_status"
	FieldDurationMS = "duration_ms"
	FieldError      = "error"
)

// Supported values for the --log-format flag.
const (
	FormatText = "text"
	FormatJSON = "json"
)

// Supported values for the --log-level flag.
const (
	LevelDebug = "debug"
	LevelInfo  = "info"
	LevelWarn  = "warn"
	LevelError = "error"
)

// Options controls how the logger is built.
type Options struct {
	// Output is where log lines are written. Mitch uses standard error so
	// that standard output stays free for command results.
	Output io.Writer

	// Format is "text" or "json".
	Format string

	// Level is the lowest level that gets written: "debug", "info", "warn" or "error".
	Level string
}

// New builds a logger from the given options.
//
// It returns an error, instead of guessing, when the format or level is not
// one of the supported values.
func New(options Options) (*slog.Logger, error) {
	if options.Output == nil {
		return nil, fmt.Errorf("logging: no output writer was given")
	}

	level, err := parseLevel(options.Level)
	if err != nil {
		return nil, err
	}

	handlerOptions := &slog.HandlerOptions{
		Level: level,
	}

	format := strings.ToLower(strings.TrimSpace(options.Format))

	var handler slog.Handler
	switch format {
	case FormatText:
		handler = slog.NewTextHandler(options.Output, handlerOptions)
	case FormatJSON:
		handler = slog.NewJSONHandler(options.Output, handlerOptions)
	default:
		return nil, fmt.Errorf(
			"logging: unsupported log format %q: use %q or %q",
			options.Format, FormatText, FormatJSON,
		)
	}

	logger := slog.New(handler)
	return logger, nil
}

// ForComponent returns a logger that adds component=<name> to every line.
// Each part of Mitch (cli, scan, store, and so on) gets its own.
func ForComponent(logger *slog.Logger, componentName string) *slog.Logger {
	componentLogger := logger.With(FieldComponent, componentName)
	return componentLogger
}

// parseLevel turns the --log-level flag value into a slog level.
func parseLevel(levelName string) (slog.Level, error) {
	normalized := strings.ToLower(strings.TrimSpace(levelName))

	switch normalized {
	case LevelDebug:
		return slog.LevelDebug, nil
	case LevelInfo:
		return slog.LevelInfo, nil
	case LevelWarn:
		return slog.LevelWarn, nil
	case LevelError:
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf(
			"logging: unsupported log level %q: use %q, %q, %q or %q",
			levelName, LevelDebug, LevelInfo, LevelWarn, LevelError,
		)
	}
}
