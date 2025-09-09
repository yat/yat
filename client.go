package yat

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"slices"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"yat.io/yat/frame"
)

type Client struct {
	tls *tls.Config
	cfg ClientConfig

	mu    sync.Mutex
	doneC chan struct{} // closed by Close
	connC chan struct{} // closed when connect returns

	// op is incremented by every subscribe operation.
	// The value before incrementing is used as the subscription number.
	op uint64

	subs map[uint64]*csub

	wbuf  []byte
	wbufC chan struct{}

	// bops are buffered operations waiting to be sent.
	// The client tracks them to keep from buffering duplicates after it reconnects.
	// Like wbuf, this set is cleared every time the buffer is flushed.
	bops map[uint64]struct{}

	// flushed is set to the current time when the buffer is flushed.
	flushed time.Time

	// flushers are blocked calls to Flush.
	// This set is cleared and the channels are closed after the buffer is flushed.
	flushers []chan<- error
}

// ClientConfig holds optional client configuration.
type ClientConfig struct {

	// Logger is where the client writes logs.
	// If it is not set, client logs are discarded.
	Logger *slog.Logger

	// DialTimeout is the amount of time the client waits for a connection.
	// If it is not set, the default dial timeout is 1 second.
	DialTimeout time.Duration

	// If ReadTimeout is set, reads will time out.
	ReadTimeout time.Duration

	// If WriteTimeout is set, writes will time out.
	WriteTimeout time.Duration

	// If KeepaliveInterval is set, the client writes a keepalive frame
	// when the interval passes without a write.
	KeepaliveInterval time.Duration
}

// DialFunc is called by the client to establish a connection to the server.
// It may be called many times from different goroutines.
type DialFunc func(context.Context) (net.Conn, error)

func NewClient(dial DialFunc, tlsConfig *tls.Config, cfg ClientConfig) (*Client, error) {
	if dial == nil {
		return nil, errors.New("dial func is nil")
	}

	if !slices.Contains(tlsConfig.NextProtos, "yat") {
		return nil, errors.New("invalid client configuration: TLSConfig.NextProtos does not include yat")
	}

	c := &Client{
		tls:   tlsConfig,
		cfg:   cfg.withDefaults(),
		doneC: make(chan struct{}),
		connC: make(chan struct{}),
		subs:  map[uint64]*csub{},
		wbufC: make(chan struct{}, 1),
		bops:  map[uint64]struct{}{},
	}

	// cancelled after the client is closed
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		<-c.doneC
		cancel()
	}()

	go func() {
		defer close(c.connC)
		c.connect(ctx, dial)
	}()

	return c, nil
}

// Publish copies m to the outbound message buffer.
// The buffer is flushed automatically when the client is connected.
// Publish returns an error if the client is closed.
func (c *Client) Publish(m Msg) error {
	if m.Topic.IsZero() {
		return nil
	}

	c.mu.Lock()

	select {
	case <-c.doneC:
		c.mu.Unlock()
		return net.ErrClosed
	default:
	}

	c.wbuf = frame.Append(c.wbuf, fMSG, msgFrameBody{
		Msg: m,
	})

	c.mu.Unlock()
	c.flush()

	return nil
}

// Subscribe arranges for deliver to be called in a new goroutine when a selected message is published.
// Call [Subscription.Stop] on the returned subscription to stop delivery.
// Subscribe returns an error if the client is closed.
//
// The message passed to deliver aliases internal buffers.
// It is an error to modify it or retain its fields after deliver returns.
func (c *Client) Subscribe(sel Sel, flags SubFlags, deliver func(Msg)) (Subscription, error) {
	c.mu.Lock()

	select {
	case <-c.doneC:
		c.mu.Unlock()
		return nil, net.ErrClosed
	default:
	}

	if sel.Topic.IsZero() || deliver == nil {
		c.mu.Unlock()
		return zsub{}, nil
	}

	num := c.op
	c.op++

	sub := &csub{
		client: c,
		num:    num,
		sel:    sel,
		flags:  flags,
		rcv:    newReceiver(sel.Limit, deliver),
		stopC:  make(chan struct{}),
	}

	c.subs[num] = sub
	c.bops[num] = struct{}{}

	c.wbuf = frame.Append(c.wbuf, fSUB, subFrameBody{
		Num:   num,
		Sel:   sel,
		Flags: flags,
	})

	c.mu.Unlock()
	c.flush()

	return sub, nil
}

// Flush waits until the client is connected, then blocks until the outbound message buffer is written.
// It returns an error if the client is closed, or if the context is canceled,
// or if an error occurs while writing the message buffers.
// If the buffer is empty, Flush does nothing and returns nil.
func (c *Client) Flush(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	c.mu.Lock()

	select {
	case <-c.doneC:
		c.mu.Unlock()
		return net.ErrClosed
	default:
	}

	if len(c.wbuf) == 0 {
		c.mu.Unlock()
		return nil
	}

	flushC := make(chan error)
	c.flushers = append(c.flushers, flushC)
	c.mu.Unlock()

	c.flush()

	select {
	case <-c.doneC:
		return net.ErrClosed

	case <-ctx.Done():
		return ctx.Err()

	case err := <-flushC:
		return err
	}
}

// Close shuts down the client.
// If the client is connected, Close waits for the connection to flush and close before returning.
// After Close is called, all methods return [net.ErrClosed].
func (c *Client) Close() error {
	c.mu.Lock()

	select {
	case <-c.doneC:
		c.mu.Unlock()
		return net.ErrClosed

	default:
		close(c.doneC)
		c.mu.Unlock()
	}

	<-c.connC
	return nil
}

func (c *Client) connect(ctx context.Context, dial DialFunc) {
	for {
		if ctx.Err() != nil {
			return
		}

		dctx, cancel := context.WithTimeout(context.Background(), c.cfg.DialTimeout)
		conn, err := dial(dctx)
		cancel()

		if err != nil {
			if err == ctx.Err() {
				return
			}

			c.cfg.Logger.WarnContext(ctx, "dial failed",
				"error", err)

			time.Sleep(1 * time.Second)
			continue
		}

		start := time.Now()
		conn = tls.Client(conn, c.tls)

		logger := c.cfg.Logger.With(
			"local", conn.LocalAddr().String(),
			"remote", conn.RemoteAddr().String())

		logger.Debug("connection opened")

		c.mu.Lock()

		var resubs int
		for num, sub := range c.subs {
			if _, pending := c.bops[num]; !pending {
				sel := sub.sel
				if sel.Limit > 0 {
					sel.Limit -= sub.rcv.NMsg()
				}

				c.wbuf = frame.Append(c.wbuf, fSUB, subFrameBody{
					Num:   num,
					Sel:   sel,
					Flags: sub.flags,
				})

				resubs++
			}
		}

		if resubs > 0 {
			c.flush()
		}

		c.mu.Unlock()

		eg, ctx := errgroup.WithContext(ctx)

		eg.Go(func() error {
			return c.readFrames(ctx, logger, conn)
		})

		eg.Go(func() error {
			return c.writeFrames(ctx, conn)
		})

		if c.cfg.KeepaliveInterval > 0 {
			eg.Go(func() error {
				return c.keepalive(ctx, conn)
			})
		}

		if err := eg.Wait(); err != nil && err != net.ErrClosed {
			logger.WarnContext(ctx, "connection failed", "error", err)
		}

		logger.DebugContext(ctx, "connection closed",
			"elapsed", time.Since(start))
	}
}

func (c *Client) readFrames(ctx context.Context, logger *slog.Logger, conn net.Conn) error {
	frames := frame.NewReader(conn)

	for {
		if to := c.cfg.ReadTimeout; to != 0 {
			conn.SetReadDeadline(time.Now().Add(to))
		}

		hdr, err := frames.Next()
		if err != nil {
			return err
		}

		var handle func(context.Context, *slog.Logger, []byte) error

		switch hdr.Type {
		case fPKG:
			handle = c.readPkgFrame
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

func (c *Client) readPkgFrame(ctx context.Context, logger *slog.Logger, rawBody []byte) error {
	var body pkgFrameBody
	if err := body.ParseFields(rawBody); err != nil {
		return err
	}

	logger.Log(ctx, slog.LevelDebug-1, "pkg frame received", "body", body)

	if body.Msg.Topic.IsZero() {
		return nil
	}

	if body.Msg.IsExpired() {
		return nil
	}

	c.mu.Lock()
	sub := c.subs[body.Num]
	c.mu.Unlock()

	if sub != nil {
		go sub.Deliver(body.Msg)
	}

	return nil

}

func (c *Client) writeFrames(ctx context.Context, conn net.Conn) error {
	defer conn.Close()

	for {
		select {
		case <-ctx.Done():
		case <-c.wbufC:
		}

		now := time.Now()

		c.mu.Lock()
		buf := c.wbuf
		flushers := c.flushers
		c.wbuf = nil
		c.flushers = nil
		c.flushed = now
		clear(c.bops)
		c.mu.Unlock()

		var err error
		if len(buf) > 0 {
			if to := c.cfg.WriteTimeout; to > 0 {
				conn.SetWriteDeadline(now.Add(to))
			}
			_, err = conn.Write(buf)
		}

		for _, f := range flushers {
			select {
			case f <- err:
			default:
			}
		}

		if err != nil {
			return err
		}

		if ctx.Err() != nil {
			return net.ErrClosed
		}
	}
}

func (c *Client) keepalive(ctx context.Context, conn net.Conn) error {
	tick := time.NewTicker(c.cfg.KeepaliveInterval)
	emptyFrame := frame.Append(nil, 0, nil)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-tick.C:
			c.mu.Lock()

			now := time.Now()
			should := len(c.wbuf) == 0 &&
				now.Sub(c.flushed) > c.cfg.KeepaliveInterval

			c.mu.Unlock()

			if should {
				if to := c.cfg.WriteTimeout; to > 0 {
					conn.SetWriteDeadline(now.Add(to))
				}

				if _, err := conn.Write(emptyFrame); err != nil {
					return err
				}
			}
		}
	}
}

func (c *Client) flush() {
	select {
	case c.wbufC <- struct{}{}:
	default:
	}
}

// called by [csub.Stop]
func (c *Client) stop(cs *csub) {
	unsub := !cs.rcv.LimitReached()

	c.mu.Lock()
	defer c.mu.Unlock()

	if unsub {
		c.wbuf = frame.Append(c.wbuf, fUNSUB, unsubFrameBody{
			Num: cs.num,
		})

		c.flush()
	}
}

func (cfg ClientConfig) withDefaults() ClientConfig {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}

	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 1 * time.Second
	}

	return cfg
}

type csub struct {
	client *Client
	num    uint64
	sel    Sel
	flags  SubFlags
	rcv    *receiver
	once   sync.Once
	stopC  chan struct{}
}

func (s *csub) Deliver(m Msg) {
	if !s.rcv.Deliver(m) {
		s.Stop()
	}
}

func (cs *csub) Stop() {
	cs.once.Do(func() {
		cs.client.stop(cs)
		close(cs.stopC)
	})
}

func (s *csub) Stopped() <-chan struct{} {
	return s.stopC
}
