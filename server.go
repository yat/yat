package yat

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/yat/yat/field"
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

	cfg ServerConfig

	mu      sync.Mutex
	wbuf    net.Buffers
	wbufC   chan struct{}
	flushed time.Time
}

// Serve serves bus to conn using the Yat protocol.
func Serve(ctx context.Context, conn net.Conn, bus *Bus, cfg ServerConfig) (err error) {
	cfg = cfg.withDefaults()

	start := time.Now()
	logger := cfg.Logger.With(
		"local", conn.LocalAddr(),
		"remote", conn.RemoteAddr())

	trace := slog.LevelDebug - 1
	logTrace := logger.Enabled(ctx, trace)

	if logTrace {
		logger.Log(ctx, trace, "connection opened")
	}

	defer func() {
		if logTrace {
			logger.Log(ctx, trace, "connection closed",
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

	sc := &svrConn{
		conn: conn,
		bus:  bus,
		cfg:  cfg,

		wbufC: make(chan struct{}, 1),
	}

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
	frames := frame.NewReader(sc.conn)
	fields := field.NewReader(nil)

	for {
		if d := sc.cfg.ReadTimeout; d != 0 {
			sc.conn.SetReadDeadline(time.Now().Add(d))
		}

		hdr, err := frames.Next()
		if err != nil {
			return err
		}

		var handle func(context.Context, *slog.Logger, *field.Reader) error

		switch hdr.Type {
		case msgFrame:
			handle = sc.readMsgFrame

		case subFrame:
			handle = sc.readSubFrame

		case unsubFrame:
			handle = sc.readUnsubFrame
		}

		body := make([]byte, hdr.BodyLen())
		if _, err := io.ReadFull(frames, body); err != nil {
			return err
		}

		fields.Reset(body)
		if err := handle(ctx, logger, fields); err != nil {
			logger.ErrorContext(ctx, "frame handler failed",
				"type", hdr.Type,
				"error", err)
		}
	}
}

func (sc *svrConn) readMsgFrame(ctx context.Context, logger *slog.Logger, r *field.Reader) error {
	var body msgFrameBody
	if err := body.ParseFields(r); err != nil {
		return err
	}

	logger.DebugContext(ctx, "read msg frame", "body", body)

	if body.Msg.Topic.IsZero() {
		return nil
	}

	if dl := body.Msg.Deadline; !dl.IsZero() && time.Now().After(dl) {
		return nil
	}

	return nil
}

func (sc *svrConn) readSubFrame(ctx context.Context, logger *slog.Logger, r *field.Reader) error {
	var body subFrameBody
	if err := body.ParseFields(r); err != nil {
		return err
	}

	logger.DebugContext(ctx, "read sub frame", "body", body)

	if body.Sel.Topic.IsZero() {
		return nil
	}

	return nil
}

func (sc *svrConn) readUnsubFrame(ctx context.Context, logger *slog.Logger, r *field.Reader) error {
	var body unsubFrameBody
	if err := body.ParseFields(r); err != nil {
		return err
	}

	logger.DebugContext(ctx, "read unsub frame", "body", body)

	return nil
}

func (sc *svrConn) WriteFrames(ctx context.Context) error {
	defer sc.conn.Close()

	for {
		select {
		case <-ctx.Done():
		case <-sc.wbufC:
		}

		now := time.Now()

		sc.mu.Lock()
		nb := sc.wbuf
		sc.wbuf = nil
		sc.flushed = now
		sc.mu.Unlock()

		if d := sc.cfg.WriteTimeout; d > 0 {
			sc.conn.SetWriteDeadline(now.Add(d))
		}

		if _, err := nb.WriteTo(sc.conn); err != nil {
			return err
		}

		if err := ctx.Err(); err != nil {
			return err
		}
	}
}

func (sc *svrConn) Keepalive(ctx context.Context) error {
	tick := time.NewTicker(sc.cfg.KeepaliveInterval)
	emptyFrame := frame.Append(nil, 0, nil)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-tick.C:
			sc.mu.Lock()

			now := time.Now()
			should := len(sc.wbuf) == 0 &&
				now.Sub(sc.flushed) > sc.cfg.KeepaliveInterval

			sc.mu.Unlock()

			if should {
				if d := sc.cfg.WriteTimeout; d > 0 {
					sc.conn.SetWriteDeadline(now.Add(d))
				}

				if _, err := sc.conn.Write(emptyFrame); err != nil {
					return err
				}
			}
		}
	}
}

func (cfg ServerConfig) withDefaults() ServerConfig {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}

	return cfg
}
