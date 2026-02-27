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

	"yat.io/yat/api"
)

type Server struct {
	router *Router
	config ServerConfig
	local  *Router
}

type ServerConfig struct {
	// Logger is where the server writes logs.
	// If it is nil, server logs are discarded.
	Logger *slog.Logger
}

type serverConn struct {
	mu    sync.Mutex
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
	local := NewRouter()

	s := &Server{
		router: router,
		config: config,
		local:  local,
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
		if errors.Is(err, net.ErrClosed) {
			s.local.Publish(Msg{Path: NewPath("$svr/events/stop")})
		}

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
	sc := &serverConn{
		subs:  map[uint64]*rent{},
		wbufC: make(chan struct{}, 1),
		Conn:  conn,
	}

	defer func() {
		if len(sc.subs) > 0 {
			rents := map[*Router][]*rent{}

			for _, e := range sc.subs {
				rents[e.rr] = append(rents[e.rr], e)
			}

			for rr, ee := range rents {
				rr.removeAll(ee)
			}
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
	_, msg, raw, err := parseMsg(body)
	if err != nil {
		return err
	}

	if isReserved(msg.Inbox) {
		return errReservedInbox
	}

	// no publishable $paths yet
	if isReserved(msg.Path) {
		return nil
	}

	ee := s.router.route(msg)
	s.router.deliver(ee, msg, raw)

	return nil
}

func (s *Server) handleSub(ctx context.Context, logger *slog.Logger, conn *serverConn, body []byte) error {
	var f api.SubFrame
	if err := proto.Unmarshal(body, &f); err != nil {
		return err
	}

	num := f.GetNum()
	p, _, err := ParsePath(f.GetPath())
	if err != nil {
		return err
	}

	rr := s.getRouter(p)

	e := &rent{
		rr: rr,

		Sel: Sel{
			Path: p,
		},

		Do: func(_ Msg, raw []byte) {
			s.deliver(conn, num, raw)
		},
	}

	conn.mu.Lock()
	old := conn.subs[num]

	// selected path is immutable
	if old != nil && !p.Equal(old.Sel.Path) {
		conn.mu.Unlock()
		return errSelPath
	}

	conn.subs[num] = e
	conn.mu.Unlock()

	rr.update(old, e)

	return nil
}

func (s *Server) handleUnsub(ctx context.Context, logger *slog.Logger, conn *serverConn, body []byte) error {
	var f api.UnsubFrame
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
		old.rr.update(old, nil)
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

func (s *Server) deliver(conn *serverConn, subNum uint64, msgFields []byte) {
	prefix := []byte{0, 0, 0, msgFrameType}
	prefix = protowire.AppendTag(prefix, numField, protowire.VarintType)
	prefix = protowire.AppendVarint(prefix, subNum)

	// frameHdr.Len
	n := len(prefix) + len(msgFields)
	prefix[0] = byte(n)
	prefix[1] = byte(n >> 8)
	prefix[2] = byte(n >> 16)

	conn.mu.Lock()
	conn.wbufs = append(conn.wbufs, prefix, msgFields)
	conn.mu.Unlock()

	select {
	case conn.wbufC <- struct{}{}:
	default:
	}
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

// getRouter returns the appropriate router for the given path.
// If the path is reserved, getRouter returns the server's internal router.
// Otherwise it returns the router passed to [NewServer].
func (s *Server) getRouter(p Path) *Router {
	switch {
	case isReserved(p):
		return s.local

	default:
		return s.router
	}
}

func (c ServerConfig) withDefaults() ServerConfig {
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}

	return c
}
