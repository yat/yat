package yat

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
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

	// ReadTimeout limits the amount of time the server waits for a read to finish.
	// If the value is <= 0 it is replaced by the default (5s).
	// If the read timeout is exceeded, the connection is closed.
	ReadTimeout time.Duration

	// WriteTimeout limits the amount of time the server waits for a write to finish.
	// If the value is <= 0 it is replaced by the default (10s).
	// If the write timeout is exceeded, the connection is closed.
	WriteTimeout time.Duration

	// KeepaliveInterval controls how often the server sends keepalive frames
	// If the value is <= 0 it is replaced by the default (1s).
	KeepaliveInterval time.Duration

	// MaxConnBufferLen limits the length of the per-connection write buffer.
	// If the value is <= 0 it is replaced by the default (16MiB).
	// Overlimit writes are logged and dropped.
	MaxConnBufferLen int

	// MaxNumConn limits the number of simultaneous connections.
	// If the value is <= 0 an unlimited number of connections is allowed.
	MaxNumConn int
}

type serverConn struct {
	mu    sync.Mutex
	subs  map[uint64]*rent
	wbufs net.Buffers
	wbufC chan struct{}
	wbufN int

	net.Conn
}

const (
	defaultReadTimeout       = 5 * time.Second
	defaultWriteTimeout      = 10 * time.Second
	defaultKeepaliveInterval = 1 * time.Second
	defaultMaxConnBufferLen  = 1 << 24
)

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

	// curently serving
	var nconn atomic.Int64

	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}

		n := nconn.Add(1)
		if max := int64(s.config.MaxNumConn); max > 0 && n > max {
			s.config.Logger.Warn("too many connections",
				"local", conn.LocalAddr(),
				"remote", conn.RemoteAddr(),
				"nconn", s.config.MaxNumConn)

			nconn.Add(-1)
			conn.Close()
			continue
		}

		wg.Go(func() {
			defer nconn.Add(-1)

			logger := s.config.Logger.With(
				"conn", uuid.New().String(),
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
			s.router.removeAll(maps.Values(sc.subs))
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
		if err := s.setReadDeadline(conn); err != nil {
			return err
		}

		hdr, err := readFrameHdr(conn)
		if err != nil {
			return err
		}

		if hdr.Len() < MinFrameLen {
			return errors.New("short frame")
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
	panic("handlePub")
}

func (s *Server) handleSub(ctx context.Context, logger *slog.Logger, conn *serverConn, body []byte) error {
	var f api.SubFrame
	if err := proto.Unmarshal(body, &f); err != nil {
		return err
	}

	p, _, err := ParsePath(f.GetPath())
	if err != nil {
		return err
	}

	e := &rent{
		Sel: Sel{
			Path: p,
		},

		Do: func(m Msg, raw []byte) {
			panic("wip")
		},
	}

	conn.mu.Lock()
	old := conn.subs[f.GetNum()]
	conn.subs[f.GetNum()] = e
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
		conn.wbufN = 0
		conn.mu.Unlock()

		if len(bufs) > 0 {
			if err := s.setWriteDeadline(conn); err != nil {
				return err
			}

			if _, err := bufs.WriteTo(conn); err != nil {
				return err
			}
		}

		if err := context.Cause(ctx); err != nil {
			return err
		}
	}
}

func (s *Server) keepalive(ctx context.Context, logger *slog.Logger, conn *serverConn) error {
	tick := time.NewTicker(s.config.KeepaliveInterval)
	keepalive := []byte{4, 0, 0, 0}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-tick.C:
			conn.mu.Lock()

			flush := false
			if free := s.config.MaxConnBufferLen - conn.wbufN; free >= len(keepalive) {
				conn.wbufs = append(conn.wbufs, keepalive)
				conn.wbufN += len(keepalive)
				flush = true
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

func (s *Server) setReadDeadline(conn net.Conn) error {
	return conn.SetReadDeadline(time.Now().Add(s.config.ReadTimeout))
}

func (s *Server) setWriteDeadline(conn net.Conn) error {
	return conn.SetWriteDeadline(time.Now().Add(s.config.WriteTimeout))
}

func (sc ServerConfig) withDefaults() ServerConfig {
	if sc.Logger == nil {
		sc.Logger = slog.New(slog.DiscardHandler)
	}

	if sc.ReadTimeout <= 0 {
		sc.ReadTimeout = defaultReadTimeout
	}

	if sc.WriteTimeout <= 0 {
		sc.WriteTimeout = defaultWriteTimeout
	}

	if sc.KeepaliveInterval <= 0 {
		sc.KeepaliveInterval = defaultKeepaliveInterval
	}

	if sc.MaxConnBufferLen <= 0 {
		sc.MaxConnBufferLen = defaultMaxConnBufferLen
	}

	if sc.MaxNumConn < 0 {
		sc.MaxNumConn = 0
	}

	return sc
}
