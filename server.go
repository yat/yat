package yat

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net"
	"slices"
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
			logger := s.config.Logger.With(
				"local", conn.LocalAddr(),
				"remote", conn.RemoteAddr(),
			)

			start := time.Now()
			logger.DebugContext(ctx, "connection opened")

			defer func() {
				logger.DebugContext(ctx, "connection closed", "elapsed", time.Since(start))
			}()

			err := s.serve(ctx, logger, conn)

			if err != nil {
				logger.ErrorContext(ctx, "connection failed", "error", err)
			}
		})
	}
}

func (s *Server) serve(ctx context.Context, logger *slog.Logger, conn net.Conn) error {
	sc := &serverConn{
		subs:  map[uint64]*rent{},
		wbufC: make(chan struct{}, 1),
		Conn:  conn,
	}

	defer func() {
		if len(sc.subs) > 0 {
			s.router.removeAll(slices.Collect(maps.Values(sc.subs)))
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
			logger.DebugContext(ctx, "discard frame", "type", hdr.Type(), "len", hdr.Len())
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

	// can't publish to $ paths
	if isSystemPath(msg.Path) {
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

	// wip
	if isSystemPath(p) {
		return nil
	}

	e := &rent{
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

	s.router.update(old, e)

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
		s.router.update(old, nil)
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

func (c ServerConfig) withDefaults() ServerConfig {
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}

	return c
}
