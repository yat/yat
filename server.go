package yat

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"yat.io/yat/wire"
)

type Server struct {
	router *Router
	config ServerConfig
}

type ServerConfig struct {
	// Logger is where the server writes logs.
	// If it is nil, server logs are discarded.
	Logger *slog.Logger

	// Rules determine which client operations are allowed.
	// If it is nil, all client operations are denied.
	Rules *RuleSet
}

type serverConn struct {
	mu sync.Mutex

	// allow decides whether client actions are allowed.
	// It is initially compiled when a connection is accepted.
	allow func(Path, Action) bool

	subs  map[uint64]*rent
	wbufs net.Buffers
	wbufC chan struct{}

	net.Conn
}

func NewServer(router *Router, config ServerConfig) (*Server, error) {
	if router == nil {
		return nil, errors.New("nil router")
	}

	config = config.withDefaults()

	s := &Server{
		router: router,
		config: config,
	}

	return s, nil
}

func (s *Server) Serve(l net.Listener) error {
	wg := &sync.WaitGroup{}
	defer wg.Wait()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}

		wg.Go(func() {
			s.ServeConn(ctx, conn)
		})
	}
}

func (s *Server) ServeConn(ctx context.Context, conn net.Conn) {
	logger := s.config.Logger.With(
		"local", conn.LocalAddr().String(),
		"remote", conn.RemoteAddr().String(),
	)

	start := time.Now()
	logger.DebugContext(ctx, "connection opened")

	defer func() {
		logger.DebugContext(ctx, "connection closed", "elapsed", time.Since(start))
	}()

	err := s.serveConn(ctx, logger, conn)

	if err != nil && err != io.EOF {
		logger.ErrorContext(ctx, "connection failed", "error", err)
	}
}

func (s *Server) serveConn(ctx context.Context, logger *slog.Logger, conn net.Conn) error {
	if tc, ok := conn.(interface{ HandshakeContext(context.Context) error }); ok {
		if err := tc.HandshakeContext(ctx); err != nil {
			conn.Close()
			return err
		}
	}

	sc := &serverConn{
		allow: func(Path, Action) bool { return false },
		subs:  map[uint64]*rent{},
		wbufC: make(chan struct{}, 1),
		Conn:  conn,
	}

	if s.config.Rules != nil {
		sc.allow = s.config.Rules.Compile(Principal{
			Conn: conn,
		})
	}

	defer func() {
		if len(sc.subs) > 0 {
			var ops []rop
			for _, e := range sc.subs {
				ops = append(ops, rop{ropDel, e})
			}
			s.router.update(ops...)
		}
	}()

	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error { return s.readFrames(ctx, logger, sc) })
	eg.Go(func() error { return s.writeFrames(ctx, logger, sc) })
	eg.Go(func() error { return s.keepalive(ctx, logger, sc) })
	return eg.Wait()
}

func (s *Server) readFrames(ctx context.Context, logger *slog.Logger, conn *serverConn) error {
	for {
		hdr, err := readFrameHdr(conn)
		if err != nil {
			return err
		}

		if hdr.Len() < MinFrameLen {
			return errShortFrame
		}

		var handle func(context.Context, *slog.Logger, *serverConn, []byte) error

		switch hdr.Type() {
		case pubFrameType:
			handle = s.handlePub

		case subFrameType:
			handle = s.handleSub

		case unsubFrameType:
			handle = s.handleUnsub

		default:
			logger.Log(ctx, slog.LevelDebug-1, "discard frame", "type", hdr.Type(), "len", hdr.Len())
			if _, err := io.CopyN(io.Discard, conn, int64(hdr.BodyLen())); err != nil {
				return err
			}
		}

		if handle == nil {
			continue
		}

		body := make([]byte, hdr.BodyLen())
		if _, err := io.ReadFull(conn, body); err != nil {
			return err
		}

		if err := handle(ctx, logger, conn, body); err != nil {
			return err
		}
	}
}

func (s *Server) handlePub(ctx context.Context, logger *slog.Logger, conn *serverConn, body []byte) error {
	fields, raw, err := parseFields(body)
	if err != nil {
		return err
	}

	if err := validatePubFrame(fields); err != nil {
		return err
	}

	var (
		pathOK  = conn.allow(fields.Msg.Path, ActionPub)
		inboxOK = fields.Msg.Inbox.IsZero() || conn.allow(fields.Msg.Inbox, ActionSub)
	)

	if !pathOK || !inboxOK {
		return nil
	}

	ee, _ := s.router.route(fields.Path)
	s.router.deliver(ee, delivery{
		Msg: fields.Msg,
		Raw: raw,
	})

	return nil
}

func (s *Server) handleSub(ctx context.Context, logger *slog.Logger, conn *serverConn, body []byte) error {
	var f wire.SubFrame
	if err := proto.Unmarshal(body, &f); err != nil {
		return err
	}

	num := f.GetNum()
	p, _, err := ParsePath(f.GetPath())
	if err != nil {
		return err
	}

	if len(f.Group) > MaxGroupLen {
		return errLongGroup
	}

	if !conn.allow(p, ActionSub) {
		return nil
	}

	sel := Sel{
		Path: p,
	}

	if f.Group != nil {
		sel.Group = NewGroup(string(f.Group))
	}

	if limit := max(0, min(f.Limit, MaxLimit)); limit > 0 {
		sel.Limit = int(limit)
	}

	if err := validateSel(sel); err != nil {
		return err
	}

	conn.mu.Lock()

	if _, dupe := conn.subs[num]; dupe {
		conn.mu.Unlock()
		return errDuplicateSub
	}

	e := &rent{
		Ext: true,
		Sel: sel,
		Do: func(d delivery) {
			s.msg(conn, num, d.Raw)
		},
	}

	// called by the router
	// to clean up limited subs
	e.unsub = sync.OnceFunc(func() {
		conn.mu.Lock()
		if conn.subs[num] == e {
			delete(conn.subs, num)
		}
		conn.mu.Unlock()
	})

	conn.subs[num] = e
	conn.mu.Unlock()

	s.router.update(rop{ropIns, e})

	return nil
}

func (s *Server) handleUnsub(ctx context.Context, logger *slog.Logger, conn *serverConn, body []byte) error {
	var f wire.UnsubFrame
	if err := proto.Unmarshal(body, &f); err != nil {
		return err
	}

	conn.mu.Lock()

	old, found := conn.subs[f.GetNum()]

	if found {
		delete(conn.subs, f.GetNum())
	}

	conn.mu.Unlock()

	if found {
		s.router.update(rop{ropDel, old})
	}

	return nil
}

func (s *Server) writeFrames(ctx context.Context, logger *slog.Logger, conn *serverConn) error {
	defer conn.Close()

	for {
		select {
		case <-ctx.Done():
		case <-conn.wbufC:
		}

		conn.mu.Lock()
		bufs := conn.wbufs
		conn.wbufs = nil
		conn.mu.Unlock()

		if len(bufs) > 0 {
			if _, err := bufs.WriteTo(conn); err != nil {
				return err
			}
		}

		if err := context.Cause(ctx); err != nil {
			return err
		}
	}
}

// msg appends a msg frame to the conn's write buffer list.
func (s *Server) msg(conn *serverConn, subNum uint64, rawFields []byte) error {
	prefix := []byte{0, 0, 0, msgFrameType}
	prefix = protowire.AppendTag(prefix, numField, protowire.VarintType)
	prefix = protowire.AppendVarint(prefix, subNum)

	// frameHdr.Len
	n := len(prefix) + len(rawFields)
	prefix[0] = byte(n)
	prefix[1] = byte(n >> 8)
	prefix[2] = byte(n >> 16)

	conn.mu.Lock()
	conn.wbufs = append(conn.wbufs, prefix, rawFields)
	conn.mu.Unlock()

	select {
	case conn.wbufC <- struct{}{}:
	default:
	}

	return nil
}

func (s *Server) keepalive(ctx context.Context, logger *slog.Logger, conn *serverConn) error {
	tick := time.NewTicker(1 * time.Second)
	keepalive := []byte{4, 0, 0, 0}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-tick.C:
			conn.mu.Lock()

			flush := len(conn.wbufs) == 0
			if flush {
				conn.wbufs = append(conn.wbufs, keepalive)
			}

			conn.mu.Unlock()

			if flush {
				select {
				case conn.wbufC <- struct{}{}:
				default:
				}
			}
		}
	}
}

func (c ServerConfig) withDefaults() ServerConfig {
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}

	return c
}
