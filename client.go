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
	"google.golang.org/protobuf/proto"
	"yat.io/yat/api"
)

type Client struct {
	config ClientConfig

	mu    sync.Mutex
	num   uint64
	subs  map[uint64]func(Msg)
	wbuf  []byte
	wbufC chan struct{}

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

func NewClient(dial DialFunc, config ClientConfig) (*Client, error) {
	if dial == nil {
		return nil, errors.New("nil dial func")
	}

	config = config.withDefaults()

	c := &Client{
		config: config,
		subs:   map[uint64]func(Msg){},
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
	<-c.connC
	return nil
}

func (c *Client) Publish(m Msg) error {
	if m.Path.IsZero() {
		return errEmptyPath
	}

	if isWild(m.Path) {
		return errWildPath
	}

	if isWild(m.Inbox) {
		return errWildInbox
	}

	if isReserved(m.Inbox) {
		return errReservedInbox
	}

	// TODO: return a less protocol-centric error here,
	// the data field is actually what's too long

	bodyLen := msgFieldsLen(m)
	frameLen := frameHdrLen + bodyLen
	if frameLen > MaxFrameLen {
		return errLongFrame
	}

	c.mu.Lock()

	select {
	case <-c.doneC:
		c.mu.Unlock()
		return net.ErrClosed
	default:
	}

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

func (c *Client) Subscribe(sel Sel, callback func(Msg)) (unsub func(), err error) {
	if sel.Path.IsZero() {
		return nil, errEmptyPath
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
	c.subs[num] = func(m Msg) {
		go callback(m)
	}

	c.wbuf = appendFrame(c.wbuf, subFrameType, func(b []byte) []byte {
		b, _ = proto.MarshalOptions{}.MarshalAppend(b, &api.SubFrame{
			Num:  num,
			Path: sel.Path.p,
		})

		return b
	})

	c.mu.Unlock()

	select {
	case c.wbufC <- struct{}{}:
	default:
	}

	unsub = sync.OnceFunc(func() {
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
				b, _ = proto.MarshalOptions{}.MarshalAppend(b, &api.UnsubFrame{Num: num})
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

	return unsub, nil
}

// connect redials in a loop until the client is closed.
// When it successfully connects,
// it serves the connection until an error occurs,
// after which the redial loop continues.
func (c *Client) connect(dial DialFunc) {
	defer close(c.connC)

	const redialWait = 250 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		select {
		case <-c.doneC:
			cancel()
		case <-ctx.Done():
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// TODO: add a reasonable timeout here
		dialCtx, cancelDial := context.WithCancel(ctx)
		conn, err := dial(dialCtx)
		cancelDial()

		if err != nil {
			c.config.Logger.ErrorContext(ctx, "dial failed", "error", err)

			select {
			case <-ctx.Done():
				return

			case <-time.After(redialWait):
				continue
			}
		}

		logger := c.config.Logger.With(
			"local", conn.LocalAddr(),
			"remote", conn.RemoteAddr(),
		)

		start := time.Now()
		logger.DebugContext(ctx, "connection opened")

		err = c.serve(ctx, logger, conn)

		logger.DebugContext(ctx, "connection closed", "elapsed", time.Since(start))
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
			logger.ErrorContext(ctx, "connection error", "error", err)
		}

		select {
		case <-ctx.Done():
			return

		case <-time.After(redialWait):
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

		if hdr.Len() < MinFrameLen {
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
	num, msg, _, err := parseMsg(body)
	if err != nil {
		return err
	}

	c.mu.Lock()
	callback := c.subs[num]
	c.mu.Unlock()

	if callback != nil {
		callback(msg)
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
		c.wbuf = nil
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
