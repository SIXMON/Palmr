// Package logger sets up the global slog logger.
//
// We use slog (stdlib) rather than a third-party logger so the binary
// stays minimal — important for the `FROM scratch` final image.
package logger

import (
	"log/slog"
	"os"
)

func Init() *slog.Logger {
	level := slog.LevelInfo
	if os.Getenv("DEBUG") == "true" {
		level = slog.LevelDebug
	}

	h := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     level,
		AddSource: false,
	})
	logger := slog.New(h)
	slog.SetDefault(logger)
	return logger
}
