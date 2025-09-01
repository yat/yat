package yat

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"time"

	"golang.org/x/sync/errgroup"
)

// ServerConfig holds optional server configuration.
type ServerConfig struct {

	// Logger is where the server writes logs.
	// If it is not set, server logs are discarded.
	Logger *slog.Logger

	// TLSConfig, if set, configures the server to use TLS.
	TLSConfig *tls.Config
}

// Serve serves bus to conn using the Yat protocol.
func Serve(ctx context.Context, conn net.Conn, bus *Bus, cfg ServerConfig) (err error) {
	cfg = cfg.withDefaults()

	start := time.Now()
	logger := cfg.Logger.With(
		"local", conn.LocalAddr(),
		"remote", conn.RemoteAddr())

	if logger.Enabled(ctx, slog.LevelDebug-1) {
		logger.DebugContext(ctx, "connection opened")
	}

	defer func() {
		if logger.Enabled(ctx, slog.LevelDebug-1) {
			logger.DebugContext(ctx, "connection closed",
				"elapsed", time.Since(start))
		}

		if err != nil && err != io.EOF {
			logger.ErrorContext(ctx, "connection error",
				"error", err)
		}
	}()

	if cfg.TLSConfig != nil {
		conn = tls.Server(conn, cfg.TLSConfig)
	}

	eg, ctx := errgroup.WithContext(ctx)

	eg.Go(func() error {
		panic("reader")
	})

	eg.Go(func() error {
		panic("writer")
	})

	eg.Go(func() error {
		panic("keepalive")
	})

	return eg.Wait()
}

func (cfg ServerConfig) withDefaults() ServerConfig {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}

	return cfg
}
