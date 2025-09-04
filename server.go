package yat

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"yat.io/yat/field"
	"yat.io/yat/frame"
	"yat.io/yat/topic"
)

type Server struct {
	bus *Bus
	cfg ServerConfig
}

// ServerConfig holds optional server configuration.
type ServerConfig struct {

	// Identify is called by the server when a connection's identity changes.
	// Every time the server reads a frame from the connection, it will call the
	// returned AuthFunc to decide if the action is allowed.
	// If Identify is nil, the server will deny all client actions.
	//
	// To disable auth and allow all actions,
	// even for unidentified connections,
	// set InsecureAllowAllActions.
	Identify IdentifyFunc

	// TLSConfig is the server's TLS configuration.
	// If it is not set, client connections are immediately closed unless InsecureAllowNoTLS is true.
	TLSConfig *tls.Config

	// Logger is where the server writes logs.
	// If it is not set, server logs are discarded.
	Logger *slog.Logger

	// If ReadTimeout is set, reads will time out.
	ReadTimeout time.Duration

	// If WriteTimeout is set, writes will time out.
	WriteTimeout time.Duration

	// If KeepaliveInterval is set, the server will write a keepalive frame
	// if the interval passes without a write.
	KeepaliveInterval time.Duration

	// InsecureAllowAllActions, if set, allows all clients to perform all actions.
	// Any configured Auth func is ignored.
	InsecureAllowAllActions bool

	// InsecureAllowNoTLS, if set, allows connections to proceed when TLSConfig is nil.
	InsecureAllowNoTLS bool
}

// IdentifyFunc is called by the server to identify a connection.
type IdentifyFunc func(ctx context.Context, conn net.Conn, token []byte) (Identity, AuthFunc, error)

func NewServer(bus *Bus, cfg ServerConfig) *Server {
	return &Server{bus, cfg}
}

func (s *Server) Serve(l net.Listener) error {
	var wg sync.WaitGroup
	defer wg.Done()

	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}

		wg.Go(func() {
			// this returns an error,
			// but ServeConn has already logged it
			ServeConn(context.Background(), conn, s.bus, s.cfg)
		})
	}
}

// ServeConn serves bus to conn according to cfg.
// Any TLS configuration is ignored: ServeConn expects the caller to handle it.
func ServeConn(ctx context.Context, conn net.Conn, bus *Bus, cfg ServerConfig) (err error) {
	cfg = cfg.withDefaults()

	start := time.Now()
	logger := cfg.Logger.With(
		"local", conn.LocalAddr().String(),
		"remote", conn.RemoteAddr().String())

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

	sc := &svrConn{
		conn:  conn,
		bus:   bus,
		cfg:   cfg,
		wbufC: make(chan struct{}, 1),
	}

	eg, ctx := errgroup.WithContext(ctx)

	eg.Go(func() error {
		return sc.readFrames(ctx, logger)
	})

	eg.Go(func() error {
		return sc.writeFrames(ctx)
	})

	if sc.cfg.KeepaliveInterval > 0 {
		eg.Go(func() error {
			return sc.keepalive(ctx)
		})
	}

	return eg.Wait()
}

// NewServerConfig returns a default configuration with reasonable timeouts.
// It panics if identify or tlsConfig are nil.
func NewServerConfig(identify IdentifyFunc, tlsConfig *tls.Config) ServerConfig {
	if identify == nil {
		panic("identify func is nil")
	}

	if tlsConfig == nil {
		panic("tls config is nil")
	}

	return ServerConfig{
		Identify:  identify,
		TLSConfig: tlsConfig,

		// FIX: make these reasonable
		ReadTimeout:       3 * time.Second,
		WriteTimeout:      3 * time.Second,
		KeepaliveInterval: 1 * time.Second,
	}.withDefaults()
}

func (cfg ServerConfig) withDefaults() ServerConfig {
	if cfg.Identify == nil {
		cfg.Identify = func(ctx context.Context, conn net.Conn, token []byte) (Identity, AuthFunc, error) {
			return Identity{}, func(topic.Path, Action) bool { return false }, nil
		}
	}

	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}

	return cfg
}

type svrConn struct {
	conn net.Conn
	bus  *Bus

	cfg ServerConfig

	mu      sync.Mutex
	auth    func(topic.Path, Action) bool
	wbuf    net.Buffers
	wbufC   chan struct{}
	flushed time.Time
}

func (sc *svrConn) readFrames(ctx context.Context, logger *slog.Logger) error {
	frames := frame.NewReader(sc.conn)
	fields := field.NewReader(nil)

	for {
		if to := sc.cfg.ReadTimeout; to != 0 {
			sc.conn.SetReadDeadline(time.Now().Add(to))
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

	logger.DebugContext(ctx, "msg frame", "msg", body.Msg)

	if body.Msg.Topic.IsZero() {
		return nil
	}

	if body.Msg.IsExpired() {
		return nil
	}

	sc.mu.Lock()
	defer sc.mu.Unlock()

	if !sc.allowMu(body.Msg.Topic, PUB) {
		return nil
	}

	return nil
}

func (sc *svrConn) readSubFrame(ctx context.Context, logger *slog.Logger, r *field.Reader) error {
	var body subFrameBody
	if err := body.ParseFields(r); err != nil {
		return err
	}

	logger.DebugContext(ctx, "sub frame",
		"num", body.Num,
		"sel", body.Sel)

	if body.Sel.Topic.IsZero() {
		return nil
	}

	sc.mu.Lock()
	defer sc.mu.Unlock()

	if !sc.allowMu(body.Sel.Topic, SUB) {
		return nil
	}

	return nil
}

func (sc *svrConn) readUnsubFrame(ctx context.Context, logger *slog.Logger, r *field.Reader) error {
	var body unsubFrameBody
	if err := body.ParseFields(r); err != nil {
		return err
	}

	logger.DebugContext(ctx, "unsub frame",
		"num", body.Num)

	return nil
}

func (sc *svrConn) writeFrames(ctx context.Context) error {
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

		if to := sc.cfg.WriteTimeout; to > 0 {
			sc.conn.SetWriteDeadline(now.Add(to))
		}

		if _, err := nb.WriteTo(sc.conn); err != nil {
			return err
		}

		if err := ctx.Err(); err != nil {
			return err
		}
	}
}

func (sc *svrConn) keepalive(ctx context.Context) error {
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
				if to := sc.cfg.WriteTimeout; to > 0 {
					sc.conn.SetWriteDeadline(now.Add(to))
				}

				if _, err := sc.conn.Write(emptyFrame); err != nil {
					return err
				}
			}
		}
	}
}

// the caller must hold sc.mu
func (sc *svrConn) allowMu(p topic.Path, a Action) bool {
	return sc.cfg.InsecureAllowAllActions || sc.auth != nil && sc.auth(p, a)
}
