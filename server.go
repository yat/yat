package yat

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"slices"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"yat.io/yat/frame"
	"yat.io/yat/nv"
	"yat.io/yat/topic"
)

type Server struct {
	bus *Bus
	tls *tls.Config
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

	// DisableAuth, if set, allows all clients to perform all actions.
	// The [AuthFunc] returned by Identify is ignored.
	DisableAuth bool
}

// IdentifyFunc is called by the server to identify a connection.
type IdentifyFunc func(ctx context.Context, conn net.Conn, token []byte) (Identity, AuthFunc, error)

func NewServer(bus *Bus, tlsConfig *tls.Config, cfg ServerConfig) (*Server, error) {
	if !slices.Contains(tlsConfig.NextProtos, "yat") {
		return nil, errors.New("invalid server TLS configuration: NextProtos does not include yat")
	}

	return &Server{bus, tlsConfig, cfg.withDefaults()}, nil
}

func (s *Server) Serve(l net.Listener) error {
	hs := &http.Server{
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){
			"yat": func(_ *http.Server, conn *tls.Conn, _ http.Handler) {
				ServeConn(context.Background(), conn, s.bus, s.cfg)
			},
		},
	}

	tl := tls.NewListener(l, s.tls)
	return hs.Serve(tl)
}

// ServeConn serves bus to conn according to cfg.
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
		subs:  map[uint64]*bsub{},
		wbufC: make(chan struct{}, 1),
	}

	defer func() {
		// clean up stragglers
		bus.delseq(maps.Values(sc.subs))
	}()

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

type svrConn struct {
	conn net.Conn
	bus  *Bus

	cfg ServerConfig

	mu      sync.Mutex
	auth    func(topic.Path, Action) bool
	subs    map[uint64]*bsub
	wbuf    net.Buffers
	wbufC   chan struct{}
	flushed time.Time
}

func (sc *svrConn) readFrames(ctx context.Context, logger *slog.Logger) error {
	frames := frame.NewReader(sc.conn)

	for {
		if to := sc.cfg.ReadTimeout; to != 0 {
			sc.conn.SetReadDeadline(time.Now().Add(to))
		}

		hdr, err := frames.Next()
		if err != nil {
			return err
		}

		var handle func(context.Context, *slog.Logger, []byte) error

		switch hdr.Type {
		case fMSG:
			handle = sc.readMsgFrame

		case fSUB:
			handle = sc.readSubFrame

		case fUNSUB:
			handle = sc.readUnsubFrame

		default:
			continue
		}

		body := make([]byte, hdr.BodyLen())
		if _, err := io.ReadFull(frames, body); err != nil {
			return err
		}

		if err := handle(ctx, logger, body); err != nil {
			logger.ErrorContext(ctx, "frame handler failed",
				"type", hdr.Type,
				"error", err)
		}
	}
}

func (sc *svrConn) readMsgFrame(ctx context.Context, logger *slog.Logger, rawBody []byte) error {
	start := time.Now()

	var body msgFrameBody
	if err := body.ParseFields(rawBody); err != nil {
		return err
	}

	if logger.Enabled(ctx, slog.LevelDebug-1) {
		logger.Log(ctx, slog.LevelDebug-1, "msg frame received", "message", body.Msg)
	}

	if body.Msg.Topic.IsZero() {
		return nil
	}

	if body.Msg.IsExpired() {
		return nil
	}

	sc.mu.Lock()
	allowed := sc.allowMu(body.Msg.Topic, PUB)
	sc.mu.Unlock()

	if !allowed {
		return nil
	}

	m := body.Msg
	m.fields = &rawBody

	ss := sc.bus.route(m)
	for _, s := range ss {
		s.Deliver(m)
	}

	if logger.Enabled(ctx, slog.LevelDebug-1) {
		logger.Log(ctx, slog.LevelDebug-1, "message delivered",
			"n", len(ss), "elapsed", time.Since(start))
	}

	return nil
}

func (sc *svrConn) readSubFrame(ctx context.Context, logger *slog.Logger, rawBody []byte) error {
	var body subFrameBody
	if err := body.ParseFields(rawBody); err != nil {
		return err
	}

	logger.DebugContext(ctx, "sub frame received",
		"num", body.Num,
		"sel", body.Sel)

	if body.Sel.Topic.IsZero() {
		return nil
	}

	sc.mu.Lock()

	if !sc.allowMu(body.Sel.Topic, SUB) {
		sc.mu.Unlock()
		return nil
	}

	num := body.Num
	deliver := func(m Msg) {
		sc.deliver(num, m)
	}

	stop := func() {
		sc.mu.Lock()
		defer sc.mu.Unlock()
		delete(sc.subs, num)
	}

	old := sc.subs[num]
	delete(sc.subs, num)

	bs := newBsub(sc.bus, body.Sel, body.Flags, deliver, stop)
	sc.subs[num] = bs

	sc.mu.Unlock()
	sc.bus.replace(old, bs)

	return nil
}

func (sc *svrConn) readUnsubFrame(ctx context.Context, logger *slog.Logger, rawBody []byte) error {
	var body unsubFrameBody
	if err := body.ParseFields(rawBody); err != nil {
		return err
	}

	logger.DebugContext(ctx, "unsub frame received",
		"num", body.Num)

	sc.mu.Lock()
	sub := sc.subs[body.Num]
	delete(sc.subs, body.Num)
	sc.mu.Unlock()

	if sub != nil {
		sc.bus.del(sub)
	}

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

func (sc *svrConn) deliver(num uint64, m Msg) {
	sc.mu.Lock()

	// add a pkg frame to the write buffer list in 2 buffers
	// 1. a prefix buffer for the frame header and the subscription number
	// 2. the existing message fields buffer

	prefix := nv.Append(frame.AppendHeader(nil, fPKG, nv.Len(num)+len(*m.fields)), num)
	sc.wbuf = append(sc.wbuf, prefix, *m.fields)

	sc.mu.Unlock()

	select {
	case sc.wbufC <- struct{}{}:
	default:
	}
}

// the caller must hold sc.mu
func (sc *svrConn) allowMu(p topic.Path, a Action) bool {
	return sc.cfg.DisableAuth || sc.auth != nil && sc.auth(p, a)
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
