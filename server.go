package yat

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/yat/yat/frame"
	"golang.org/x/sync/errgroup"
)

// ServerConfig holds optional server configuration.
type ServerConfig struct {

	// Logger is where the server writes logs.
	// If it is not set, server logs are discarded.
	Logger *slog.Logger

	// TLSConfig, if set, configures the server to use TLS.
	TLSConfig *tls.Config

	// If ReadTimeout is set, reads will time out.
	ReadTimeout time.Duration

	// If WriteTimeout is set, writes will time out.
	WriteTimeout time.Duration

	// If KeepaliveInterval is set, the server will write a keepalive frame
	// if the interval passes without a write.
	KeepaliveInterval time.Duration
}

type svrConn struct {
	conn net.Conn
	bus  *Bus
	cfg  ServerConfig
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

	sc := &svrConn{conn, bus, cfg}
	eg, ctx := errgroup.WithContext(ctx)

	eg.Go(func() error {
		return sc.ReadFrames(ctx, logger)
	})

	eg.Go(func() error {
		return sc.WriteFrames(ctx)
	})

	if cfg.KeepaliveInterval > 0 {
		eg.Go(func() error {
			return sc.Keepalive(ctx)
		})
	}

	return eg.Wait()
}

func (sc *svrConn) ReadFrames(ctx context.Context, logger *slog.Logger) error {
	fr := frame.NewReader(sc.conn)

	for {
		hdr, err := fr.Next()
		if err != nil {
			return err
		}

		switch hdr.Type {
		case msgFrame:
		case subFrame:
		case unsubFrame:
		}

		if err != nil {
			logger.ErrorContext(ctx, "frame handler failed",
				"type", hdr.Type,
				"error", err)
		}
	}
}

func (sc *svrConn) WriteFrames(ctx context.Context) error {
	panic("WriteFrames")
}

func (sc *svrConn) Keepalive(ctx context.Context) error {
	panic("Keepalive")
}

func (cfg ServerConfig) withDefaults() ServerConfig {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}

	return cfg
}
