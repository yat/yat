package yat

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v5"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"yat.io/yat/wire"
)

type Client struct {
	config ClientConfig

	mu   sync.Mutex
	num  uint64
	subs map[uint64]*clientSub

	// bsub holds the numbers of buffered SubFrames, cleared when the
	// buffer is flushed. The connect loop uses bsub to decide if it
	// should re-buffer a subscription.
	bsub []uint64

	wbuf  []byte
	wbufC chan struct{}

	// wbufD tracks total buffered [Msg.Data] bytes in wbuf.
	// Publish will fail if it exceeds [maxClientDataLen].
	wbufD int

	// doneC is closed by Close.
	doneC chan struct{}

	// connC is closed after connect returns.
	connC chan struct{}
}

type ClientConfig struct {
	// Logger is where the client writes logs.
	// If it is nil, client logs are discarded.
	Logger *slog.Logger
}

type DialFunc func(context.Context) (net.Conn, error)

type clientSub struct {
	Sel Sel
	Do  func(delivery)
	n   atomic.Uint64

	doneC chan struct{}
	unsub func()
}

func NewClient(dial DialFunc, config ClientConfig) (*Client, error) {
	if dial == nil {
		return nil, errors.New("nil dial func")
	}

	config = config.withDefaults()

	c := &Client{
		config: config,
		subs:   map[uint64]*clientSub{},
		wbufC:  make(chan struct{}, 1),
		doneC:  make(chan struct{}),
		connC:  make(chan struct{}),
	}

	go c.connect(dial)

	return c, nil
}

func (c *Client) Close() error {
	c.mu.Lock()

	select {
	case <-c.doneC:
		c.mu.Unlock()
		return net.ErrClosed
	default:
	}

	close(c.doneC)
	c.mu.Unlock()

	// unblock [Sub.Done]
	for _, cs := range c.subs {
		cs.unsub()
	}

	<-c.connC
	return nil
}

// Publish publishes a copy of the message.
func (c *Client) Publish(ctx context.Context, m Msg) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if err := validateMsg(m); err != nil {
		return err
	}

	c.mu.Lock()

	select {
	case <-c.doneC:
		c.mu.Unlock()
		return net.ErrClosed
	default:
	}

	if c.wbufD+len(m.Data) > maxClientDataLen {
		c.mu.Unlock()
		return errBufferFull
	}

	c.wbufD += len(m.Data)
	c.wbuf = appendFrame(c.wbuf, pubFrameType, func(b []byte) []byte {
		return appendMsgFields(b, m)
	})

	c.mu.Unlock()

	select {
	case c.wbufC <- struct{}{}:
	default:
	}

	return nil
}

// Subscribe arranges for the callback func to be called in a new goroutine
// when a selected message is published.
//
// Call [Sub.Cancel] to unsubscribe.
//
// The callback func must not retain or modify delivered messages.
func (c *Client) Subscribe(sel Sel, callback func(context.Context, Msg)) (Sub, error) {
	if err := validateSel(sel); err != nil {
		return nil, err
	}

	if callback == nil {
		return nil, errNilCallback
	}

	c.mu.Lock()
	select {
	case <-c.doneC:
		c.mu.Unlock()
		return nil, net.ErrClosed
	default:
	}

	c.num++
	num := c.num

	doneC := make(chan struct{})

	cs := &clientSub{
		Sel: sel,
		Do: func(d delivery) {
			ctx := d.Ctx
			if ctx == nil {
				ctx = context.Background()
			}
			go callback(ctx, d.Msg)
		},

		doneC: doneC,
	}

	cs.unsub = sync.OnceFunc(func() {
		close(doneC)
		c.mu.Lock()

		select {
		case <-c.doneC:
			c.mu.Unlock()
			return
		default:
		}

		var ok bool
		if _, ok = c.subs[num]; ok {
			delete(c.subs, num)
			c.wbuf = appendFrame(c.wbuf, unsubFrameType, func(b []byte) []byte {
				b, _ = proto.MarshalOptions{}.MarshalAppend(b, &wire.UnsubFrame{Num: num})
				return b
			})
		}

		c.mu.Unlock()

		if ok {
			select {
			case c.wbufC <- struct{}{}:
			default:
			}
		}
	})

	c.bsub = append(c.bsub, num)
	c.subs[num] = cs

	c.wbuf = appendSubFrame(c.wbuf, num, sel)
	c.mu.Unlock()

	select {
	case c.wbufC <- struct{}{}:
	default:
	}

	return cs, nil
}

// connect redials in a loop until the client is closed.
// When it successfully connects,
// it serves the connection until an error occurs,
// after which the redial loop continues.
func (c *Client) connect(dial DialFunc) {
	defer close(c.connC)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		select {
		case <-c.doneC:
			cancel()
		case <-ctx.Done():
		}
	}()

	redialBackoff := &backoff.ExponentialBackOff{
		InitialInterval:     200 * time.Millisecond,
		RandomizationFactor: 0.5,
		Multiplier:          1.6,
		MaxInterval:         5 * time.Second,
	}

	var ndial int

	for {
		c.mu.Lock()
		buffered := len(c.wbuf) > 0
		c.mu.Unlock()

		// stop if the client is done
		// unless this is the first dial
		// and there's something in the write buffer,
		// in which case try to connect and flush

		select {
		case <-ctx.Done():
			if ndial > 0 || !buffered {
				return
			}
		default:
		}

		dctx := ctx
		if ndial == 0 && buffered {
			dctx = context.Background()
		}

		dctx, cancel := context.WithTimeout(dctx, 3*time.Second)
		conn, err := dial(dctx)
		cancel()
		ndial++

		if err != nil {
			c.config.Logger.ErrorContext(ctx, "dial failed", "error", err)

			select {
			case <-ctx.Done():
				return

			case <-time.After(redialBackoff.NextBackOff()):
				continue
			}
		}

		redialBackoff.Reset()
		start := time.Now()

		logger := c.config.Logger.With(
			"local", conn.LocalAddr().String(),
			"remote", conn.RemoteAddr().String())

		switch ndial {
		case 1:
			logger.DebugContext(ctx, "connection opened")

		default:
			logger.InfoContext(ctx, "connection established")
		}

		c.mu.Lock()

		var resubbed bool
		for num, sub := range c.subs {
			if slices.Contains(c.bsub, num) {
				continue
			}

			logger.DebugContext(ctx, "resubscribe",
				"num", num, "path", sub.Sel.Path)

			resubbed = true
			c.bsub = append(c.bsub, num)
			c.wbuf = appendSubFrame(c.wbuf, num, sub.Sel)
		}

		c.mu.Unlock()

		if resubbed {
			select {
			case c.wbufC <- struct{}{}:
			default:
			}
		}

		err = c.serve(ctx, logger, conn)

		logger.DebugContext(ctx, "connection closed", "elapsed", time.Since(start))
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
			logger.ErrorContext(ctx, "connection error", "error", err)
		}

		select {
		case <-ctx.Done():
			return

		case <-time.After(redialBackoff.NextBackOff()):
			continue
		}
	}
}

func (c *Client) serve(ctx context.Context, logger *slog.Logger, conn net.Conn) error {
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error { return c.readFrames(ctx, logger, conn) })
	eg.Go(func() error { return c.writeFrames(ctx, logger, conn) })
	eg.Go(func() error { return c.keepalive(ctx) })
	return eg.Wait()
}

func (c *Client) readFrames(ctx context.Context, logger *slog.Logger, conn net.Conn) error {
	for {
		hdr, err := readFrameHdr(conn)
		if err != nil {
			return err
		}

		if hdr.Len() < minFrameLen {
			return errShortFrame
		}

		var handle func(context.Context, *slog.Logger, []byte) error

		switch hdr.Type() {
		case msgFrameType:
			handle = c.handleMsg

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

		if err := handle(ctx, logger, body); err != nil {
			return err
		}
	}
}

func (c *Client) handleMsg(ctx context.Context, logger *slog.Logger, body []byte) error {
	fields, _, err := parseFields(body)
	if err != nil {
		return err
	}

	if err := validateMsg(fields.Msg); err != nil {
		return err
	}

	c.mu.Lock()
	sub := c.subs[fields.Num]
	c.mu.Unlock()

	if sub != nil {
		n := sub.n.Add(1)
		lim := uint64(sub.Sel.Limit)

		if lim == 0 || n <= lim {
			sub.Do(delivery{Msg: fields.Msg})
		}

		if lim > 0 && n >= lim {
			sub.unsub()
		}
	}

	return nil
}

func (c *Client) writeFrames(ctx context.Context, logger *slog.Logger, conn net.Conn) error {
	defer conn.Close()

	for {
		var err error
		select {
		case <-ctx.Done():
			err = context.Cause(ctx)
		case <-c.wbufC:
		}

		c.mu.Lock()
		buf := c.wbuf
		c.bsub = nil
		c.wbuf = nil
		c.wbufD = 0
		c.mu.Unlock()

		if len(buf) > 0 {
			if _, err := conn.Write(buf); err != nil {
				return err
			}
		}

		if err != nil {
			return err
		}
	}
}

func (c *Client) keepalive(ctx context.Context) error {
	tick := time.NewTicker(1 * time.Second)
	keepalive := []byte{4, 0, 0, 0}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-tick.C:
			c.mu.Lock()

			flush := len(c.wbuf) == 0
			if flush {
				c.wbuf = append(c.wbuf, keepalive...)
			}

			c.mu.Unlock()

			if flush {
				select {
				case c.wbufC <- struct{}{}:
				default:
				}
			}
		}
	}
}

func (c ClientConfig) withDefaults() ClientConfig {
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}

	return c
}

func (cs *clientSub) Cancel() {
	cs.unsub()
}

func (cs *clientSub) Done() <-chan struct{} {
	return cs.doneC
}
