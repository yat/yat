package yat

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
	"yat.io/yat/wire"
)

type Conn struct {
	mu sync.Mutex

	err   error
	doneC chan struct{}
	runC  chan struct{}

	wbuf  []byte
	wbufC chan struct{}

	lastID   wire.ID
	handlers map[wire.ID]pkgHandler
}

type pkgHandler interface {
	Handle(m Msg, err error) (ok bool)
}

const (
	clientMaxFrameLen       = 1 << 23
	clientReadHeaderTimeout = 30 * time.Second
	clientReadBodyTimeout   = 10 * time.Second
	clientWriteTimeout      = 10 * time.Second
	clientKeepaliveInterval = serverReadHeaderTimeout / 2
)

var (
	connAPIFlush = NewPath("$conn/api/Flush")
)

func NewConn(conn net.Conn) *Conn {
	cc := &Conn{
		doneC:    make(chan struct{}),
		runC:     make(chan struct{}),
		wbufC:    make(chan struct{}, 1),
		handlers: map[wire.ID]pkgHandler{},
	}

	go cc.run(conn)

	return cc
}

func (cc *Conn) Publish(m Msg) error {
	if m.Path.IsZero() {
		return errMissingPath
	}

	cc.mu.Lock()

	if cc.isClosed() {
		cc.mu.Unlock()
		return net.ErrClosed
	}

	cc.wbuf = wire.AppendFrame(cc.wbuf, wire.FPUB, wire.PubFrameBody{
		Msg: m.wire(),
	}.Encode)

	cc.mu.Unlock()
	cc.wnotify()

	return nil
}

func (cc *Conn) Request(ctx context.Context, path Path, data []byte, f func(Msg) error) error {
	if path.IsZero() {
		return errMissingPath
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	cc.mu.Lock()

	if cc.isClosed() {
		cc.mu.Unlock()
		return net.ErrClosed
	}

	id := cc.nextID()
	rC := make(reqHandler)
	cc.handlers[id] = rC

	got := false
	defer func() {
		if got || ctx.Err() == nil {
			return
		}

		cc.mu.Lock()
		defer cc.mu.Unlock()
		delete(cc.handlers, id)
	}()

	cc.wbuf = wire.AppendFrame(cc.wbuf, wire.FREQ, wire.ReqFrameBody{
		ID:   id,
		Data: data,
		Path: path.data,
	}.Encode)

	cc.mu.Unlock()
	cc.wnotify()

	var res response

	select {
	case <-ctx.Done():
		return ctx.Err()

	case <-cc.Done():
		return cc.Err()

	case res = <-rC:
		got = true
	}

	if res.Err != nil {
		return res.Err
	}

	return f(res.Msg)
}

func (cc *Conn) Subscribe(sel Sel, f func(Msg)) (Sub, error) {
	if sel.Path.IsZero() {
		return nil, errMissingPath
	}

	if sel.Limit < 0 {
		return nil, errNegativeLimit
	}

	cc.mu.Lock()

	if cc.isClosed() {
		cc.mu.Unlock()
		return nil, net.ErrClosed
	}

	id := cc.nextID()
	h := &subHandler{
		do:    f,
		sel:   sel,
		unsub: func() { cc.unsub(id) },
		doneC: make(chan struct{}),
	}

	cc.handlers[id] = h
	cc.wbuf = wire.AppendFrame(cc.wbuf, wire.FSUB, wire.SubFrameBody{
		ID:    id,
		Limit: uint32(sel.Limit),
		Path:  sel.Path.data,
		Group: []byte(sel.Group.String()),
	}.Encode)

	cc.mu.Unlock()
	cc.wnotify()

	return h, nil
}

// Flush blocks until the server has processed all previous client operations.
func (cc *Conn) Flush(ctx context.Context) error {
	return cc.Request(ctx, connAPIFlush, nil, func(Msg) error { return nil })
}

// Close waits for the write buffer to flush before closing the connection.
func (cc *Conn) Close() error {
	cc.mu.Lock()

	if cc.isClosed() {
		cc.mu.Unlock()
		return net.ErrClosed
	}

	close(cc.doneC)
	if cc.err == nil {
		cc.err = net.ErrClosed
	}

	// stop all subs
	for _, h := range cc.handlers {
		if h, ok := h.(*subHandler); ok {
			h.stop(false)
		}
	}

	cc.mu.Unlock()
	<-cc.runC

	return nil
}

// Done returns a channel that is closed when the connection closes.
func (cc *Conn) Done() <-chan struct{} {
	return cc.doneC
}

// Err returns the error that caused the connection to close.
// It returns nil while the connection is open.
func (cc *Conn) Err() error {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.err
}

func (cc *Conn) run(conn net.Conn) {
	defer cc.Close()

	// unblock Close
	defer close(cc.runC)

	// clean up the conn
	defer conn.Close()

	eg, ctx := errgroup.WithContext(context.Background())

	eg.Go(func() error {
		return cc.readFrames(ctx, conn)
	})

	eg.Go(func() error {
		return cc.writeFrames(ctx, conn)
	})

	eg.Go(func() error {
		return cc.keepalive(ctx)
	})

	err := eg.Wait()

	cc.mu.Lock()
	defer cc.mu.Unlock()

	if cc.err == nil {
		cc.err = err
	}
}

func (cc *Conn) readFrames(ctx context.Context, conn net.Conn) error {
	var hdr wire.FrameHdr

	for {
		if err := conn.SetReadDeadline(time.Now().Add(clientReadHeaderTimeout)); err != nil {
			return err
		}

		if err := wire.ReadFrameHdr(conn, &hdr); err != nil {
			return err
		}

		if hdr.Len > clientMaxFrameLen {
			return errLongFrame
		}

		if err := conn.SetReadDeadline(time.Now().Add(clientReadBodyTimeout)); err != nil {
			return err
		}

		var handle func(ctx context.Context, body []byte) error

		switch hdr.Type {
		case wire.FPKG:
			handle = cc.handlePkgFrame

		case wire.FERR:
			handle = cc.handleErrFrame

		default:
			if _, err := io.CopyN(io.Discard, conn, int64(hdr.BodyLen())); err != nil {
				return fmt.Errorf("discard frame type %d: %v", hdr.Type, err)
			}

			continue
		}

		body := make([]byte, hdr.BodyLen())
		if _, err := io.ReadFull(conn, body); err != nil {
			return fmt.Errorf("read frame type %d: %v", hdr.Type, err)
		}

		if err := handle(ctx, body); err != nil {
			return fmt.Errorf("handle frame type %d: %v", hdr.Type, err)
		}
	}
}

func (cc *Conn) handlePkgFrame(ctx context.Context, b []byte) error {
	var body wire.PkgFrameBody
	if _, err := body.Decode(b); err != nil {
		return err
	}

	cc.mu.Lock()
	h := cc.handlers[body.ID]
	cc.mu.Unlock()

	if h == nil {
		return nil
	}

	var m Msg
	if err := m.parse(body.Msg); err != nil {
		return err
	}

	if !h.Handle(m, nil) {
		cc.mu.Lock()
		delete(cc.handlers, body.ID)
		cc.mu.Unlock()
	}

	return nil
}

func (cc *Conn) handleErrFrame(ctx context.Context, b []byte) error {
	var body wire.ErrFrameBody
	if _, err := body.Decode(b); err != nil {
		return err
	}

	cc.mu.Lock()
	h := cc.handlers[body.ID]
	cc.mu.Unlock()

	if h == nil || body.Errno == 0 {
		return nil
	}

	if !h.Handle(Msg{}, Errno(body.Errno)) {
		cc.mu.Lock()
		delete(cc.handlers, body.ID)
		cc.mu.Unlock()
	}

	return nil
}

func (cc *Conn) writeFrames(ctx context.Context, conn net.Conn) (err error) {
	defer conn.Close()

	for {
		select {
		case <-ctx.Done():
			err = ctx.Err()

		case <-cc.doneC:
			err = net.ErrClosed

		case <-cc.wbufC:
			err = nil
		}

		cc.mu.Lock()
		buf := cc.wbuf
		cc.wbuf = nil
		cc.mu.Unlock()

		if len(buf) > 0 {
			if err := conn.SetWriteDeadline(time.Now().Add(clientWriteTimeout)); err != nil {
				return fmt.Errorf("set write buffer deadline: %w", err)
			}

			if _, err := conn.Write(buf); err != nil {
				return fmt.Errorf("write buffer: %w", err)
			}
		}

		if err != nil {
			return
		}
	}
}

func (cc *Conn) keepalive(ctx context.Context) error {
	tickC := time.Tick(clientKeepaliveInterval)

	for {
		select {
		case <-cc.doneC:
			return nil

		case <-ctx.Done():
			return ctx.Err()

		case <-tickC:
			cc.mu.Lock()

			var wrote bool
			if len(cc.wbuf) == 0 {
				cc.wbuf = wire.AppendFrame(cc.wbuf, wire.FREQ, wire.ReqFrameBody{
					Path: connAPIFlush.data,
				}.Encode)
				wrote = true
			}

			cc.mu.Unlock()

			if wrote {
				cc.wnotify()
			}
		}
	}
}

func (cc *Conn) unsub(id wire.ID) {
	cc.mu.Lock()

	if _, ok := cc.handlers[id]; !ok {
		cc.mu.Unlock()
		return
	}

	delete(cc.handlers, id)
	cc.wbuf = wire.AppendFrame(cc.wbuf, wire.FUNSUB,
		wire.UnsubFrameBody{
			ID: id,
		}.Encode)

	cc.mu.Unlock()
	cc.wnotify()
}

// isClosed returns true if the conn is closed.
// The caller must hold mu.
func (cc *Conn) isClosed() bool {
	select {
	case <-cc.doneC:
		return true
	default:
		return false
	}
}

// nextID increments and returns the id counter.
// The caller must hold mu.
func (cc *Conn) nextID() wire.ID {
	cc.lastID++
	return cc.lastID
}

// wnotify notifies the writer of new buffers.
func (cc *Conn) wnotify() {
	select {
	case cc.wbufC <- struct{}{}:
	default:
	}
}

type reqHandler chan response

type response struct {
	Msg Msg
	Err error
}

func (h reqHandler) Handle(m Msg, err error) (ok bool) {
	select {
	case h <- response{m, err}:
	default:
	}
	return false
}

type subHandler struct {
	sel   Sel
	do    func(Msg)
	unsub func()

	n atomic.Uint64

	stopO sync.Once
	doneC chan struct{}
}

func (h *subHandler) Handle(m Msg, err error) (ok bool) {
	if err != nil {
		panic(err)
	}

	lim := uint64(h.sel.Limit)
	ltd := lim != 0
	n := h.n.Add(1)

	ok = !ltd || n < lim
	if !ltd || n <= lim {
		go func() {
			h.do(m)
			if !ok {
				h.stop(false)
			}
		}()
	}

	return
}

// implements Sub
func (h *subHandler) Stop() {
	h.stop(true)
}

func (h *subHandler) Done() <-chan struct{} {
	return h.doneC
}

func (h *subHandler) stop(unsub bool) {
	h.stopO.Do(func() {
		close(h.doneC)
		if !unsub {
			return
		}

		if lim := uint64(h.sel.Limit); lim == 0 || h.n.Load() < lim {
			h.unsub()
		}
	})
}
