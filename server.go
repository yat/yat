package yat

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/net/http2"
	"golang.org/x/sync/errgroup"
	"yat.io/yat/wire"
)

type Server struct {
	tls *tls.Config
	cfg ServerConfig
}

// ServerConfig configures server behavior.
// The zero ServerConfig is a valid configuration.
type ServerConfig struct {

	// Auth configures the server's token validation and access control rules.
	// If it is nil, all client actions will fail.
	Auth *Auth

	// Logger is where the server writes logs.
	// If it is nil, server logs are discarded.
	Logger *slog.Logger

	// Router is the message router shared by all connections.
	// If it is nil, the server uses an internal router.
	Router *Router
}

type serverConn struct {
	cfg  ServerConfig
	conn net.Conn
	id   uuid.UUID

	mu    sync.Mutex
	allow func(Path, Action) bool
	subs  map[wire.ID]*rsub
	wbufs net.Buffers
	wbufC chan struct{}

	// The conn generates a reply path for every request it handles.
	// The first time [serverConn.appendReplyPath] is called, it creates
	// a cipher (replyAEAD) based on a random 32-byte key and
	// a replyPrefix in the form "@/$b64(rr.id)/$b64(sc.id)/".
	// Then it uses replyPrefix to create a wildcard replySub.
	// Deliveries are routed to [serverConn.reply].

	replySetup  sync.Once
	replyAEAD   cipher.AEAD
	replyPrefix []byte
	replySub    *rsub
}

const (
	serverMaxFrameLen       = 1 << 23
	serverReadHeaderTimeout = 30 * time.Second
	serverReadBodyTimeout   = 10 * time.Second
	serverWriteTimeout      = 10 * time.Second
	serverReplyPathTimeout  = 1 * time.Hour
)

var errAtPath = errors.New("@ paths are publish-only")

// NewServer creates and configures a new Yat server.
// The given TLS configuration must contain at least one certificate
// or set GetCertificate.
func NewServer(tc *tls.Config, cfg ServerConfig) (*Server, error) {
	if len(tc.Certificates) == 0 && tc.GetCertificate == nil {
		return nil, errors.New("invalid TLS configuration: no certificates")
	}

	cfg = cfg.withDefaults()

	if cfg.Auth == nil {
		cfg.Logger.Warn("client auth is not configured")
	}

	svr := &Server{
		tls: tc,
		cfg: cfg,
	}

	return svr, nil
}

// Serve serves connections accepted from l.
// It always returns a non-nil error and closes l.
func (s *Server) Serve(l net.Listener) error {
	tc := s.tls.Clone()
	tl := tls.NewListener(l, tc)

	hs := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, "ѣ")
		}),

		TLSConfig: tc,
	}

	// wire up http/2
	http2.ConfigureServer(hs, nil)

	// clean up after ConfigureServer
	delete(hs.TLSNextProto, "unencrypted_http2")
	tc.NextProtos = []string{"h2", "y0"}

	// http/2 only, no h2c or http/1
	hs.Protocols = new(http.Protocols)
	hs.Protocols.SetHTTP2(true)

	// the yat client protocol, version 0
	hs.TLSNextProto["y0"] = func(_ *http.Server, c *tls.Conn, _ http.Handler) {
		s.serveClient(context.Background(), c)
	}

	return hs.Serve(tl)
}

func (s *Server) serveClient(ctx context.Context, conn *tls.Conn) {
	defer conn.Close()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	logger := s.cfg.Logger.With(
		"conn", uuid.New().String(),
		"remote", conn.RemoteAddr().String(),
		"local", conn.LocalAddr().String())

	start := time.Now()
	logger.DebugContext(ctx, "connection opened")

	defer func() {
		logger.DebugContext(ctx, "connection closed",
			"elapsed", time.Since(start).Seconds())
	}()

	sc := newServerConn(conn, s.cfg)
	defer sc.unroute()

	err := sc.Serve(ctx)
	if err == io.EOF {
		err = nil
	}

	if err != nil {
		logger.ErrorContext(ctx, "connection error", "error", err)
	}
}

// Serve serves the given router to conn using the binary protocol.
func Serve(ctx context.Context, conn net.Conn, cfg ServerConfig) error {
	defer conn.Close()

	if err := ctx.Err(); err != nil {
		return err
	}

	cfg = cfg.withDefaults()
	sc := newServerConn(conn, cfg)
	defer sc.unroute()

	return sc.Serve(ctx)
}

func newServerConn(conn net.Conn, cfg ServerConfig) *serverConn {
	address, _ := netip.ParseAddrPort(conn.RemoteAddr().String())
	allow := cfg.Auth.Compile(AuthContext{
		Address: address,
	})

	return &serverConn{
		cfg:   cfg,
		conn:  conn,
		id:    uuid.New(),
		allow: allow,
		subs:  map[wire.ID]*rsub{},
		wbufC: make(chan struct{}, 1),
	}
}

func (sc *serverConn) Serve(ctx context.Context) error {
	eg, ctx := errgroup.WithContext(ctx)

	eg.Go(func() error {
		return sc.readFrames(ctx)
	})

	eg.Go(func() error {
		return sc.writeFrames(ctx)
	})

	return eg.Wait()
}

func (sc *serverConn) readFrames(ctx context.Context) error {
	var hdr wire.FrameHdr

	for {
		if err := sc.conn.SetReadDeadline(time.Now().Add(serverReadHeaderTimeout)); err != nil {
			return err
		}

		if err := wire.ReadFrameHdr(sc.conn, &hdr); err != nil {
			return err
		}

		if hdr.Len > serverMaxFrameLen {
			return errLongFrame
		}

		if err := sc.conn.SetReadDeadline(time.Now().Add(serverReadBodyTimeout)); err != nil {
			return err
		}

		var handle func(ctx context.Context, body []byte) error

		switch hdr.Type {
		case wire.FPUB:
			handle = sc.handlePubFrame

		case wire.FREQ:
			handle = sc.handleReqFrame

		case wire.FSUB:
			handle = sc.handleSubFrame

		case wire.FUNSUB:
			handle = sc.handleUnsubFrame

		default:
			if _, err := io.CopyN(io.Discard, sc.conn, int64(hdr.BodyLen())); err != nil {
				return fmt.Errorf("discard frame type %d: %v", hdr.Type, err)
			}

			continue
		}

		body := make([]byte, hdr.BodyLen())
		if _, err := io.ReadFull(sc.conn, body); err != nil {
			return fmt.Errorf("read frame type %d: %v", hdr.Type, err)
		}

		if err := handle(ctx, body); err != nil {
			return fmt.Errorf("handle frame type %d: %v", hdr.Type, err)
		}
	}
}

func (sc *serverConn) handlePubFrame(ctx context.Context, b []byte) error {
	var body wire.PubFrameBody
	_, err := body.Decode(b)
	if err != nil {
		return err
	}

	var m Msg
	if err := m.parse(body.Msg); err != nil {
		return err
	}

	// no publishable $paths yet
	if m.Path.IsSpecialPath() {
		return nil
	}

	// clients can't subscribe to @paths, so
	if m.Reply.IsAtPath() {
		return errAtPath
	}

	if !sc.allow(m.Path, PubAction) {
		// FIX: debug log
		return nil
	}

	subs := sc.cfg.Router.route(m)
	sc.cfg.Router.deliver(subs, rmsg{
		Msg: m,
		Buf: b,
	})

	return nil
}

func (sc *serverConn) handleReqFrame(ctx context.Context, b []byte) error {
	var body wire.ReqFrameBody
	n, err := body.Decode(b)
	if err != nil {
		return err
	}

	path, _, err := ParsePath(body.Path)
	if err != nil {
		return sc.fail(body.ID, EINVAL)
	}

	// can't req @paths
	if path.IsAtPath() {
		return sc.fail(body.ID, EINVAL)
	}

	// don't route $paths
	if path.IsSpecialPath() {
		return sc.handleSpecialRequest(path, body.ID, body.Data)
	}

	if !sc.allow(path, PubAction) {
		return sc.fail(body.ID, EPERM)
	}

	b = b[:n]
	i := len(b)
	b = sc.appendReplyPath(b, body.ID)
	binary.LittleEndian.PutUint16(b[14:], uint16(len(b)-i))

	var wm wire.Msg
	if _, err := wm.Decode(b[8:]); err != nil {
		return err
	}

	rm := rmsg{Buf: b[8:]}
	rm.Msg.parse(wm)

	subs := sc.cfg.Router.route(rm.Msg)
	responder := slices.ContainsFunc(subs, func(rs *rsub) bool {
		return rs.Sel.Flags&SRES != 0
	})

	if !responder {
		return sc.fail(body.ID, ENOENT)
	}

	sc.cfg.Router.deliver(subs, rm)

	return nil
}

func (sc *serverConn) handleSubFrame(ctx context.Context, b []byte) error {
	var body wire.SubFrameBody
	_, err := body.Decode(b)
	if err != nil {
		return err
	}

	sel := Sel{
		Flags: SelFlags(body.Flags),
		Limit: int(body.Limit),
	}

	sel.Path, _, err = ParsePath(body.Path)
	if err != nil {
		return err
	}

	// can't sub to @paths
	if sel.Path.IsAtPath() {
		return errAtPath
	}

	// no subscribable $paths yet
	if sel.Path.IsSpecialPath() {
		return nil
	}

	if !sc.allow(sel.Path, SubAction) {
		//FIX: log
		return nil
	}

	sel.Group = NewGroup(string(body.Group))

	rs := &rsub{
		ID:      body.ID,
		Sel:     sel,
		Deliver: sc.deliver,
		Forget:  sc.forget,
	}

	sc.mu.Lock()
	old := sc.subs[rs.ID]
	sc.subs[rs.ID] = rs
	sc.mu.Unlock()

	sc.cfg.Router.swap(old, rs)

	return nil
}

func (sc *serverConn) handleUnsubFrame(ctx context.Context, b []byte) error {
	var body wire.UnsubFrameBody
	_, err := body.Decode(b)
	if err != nil {
		return err
	}

	sc.mu.Lock()
	rs := sc.subs[body.ID]
	delete(sc.subs, body.ID)
	sc.mu.Unlock()

	sc.cfg.Router.swap(rs, nil)

	return nil
}

func (sc *serverConn) writeFrames(ctx context.Context) error {
	defer sc.conn.Close()

	for {
		select {
		case <-ctx.Done():
		case <-sc.wbufC:
		}

		sc.mu.Lock()
		nb := sc.wbufs
		sc.wbufs = nil
		sc.mu.Unlock()

		if err := sc.conn.SetWriteDeadline(time.Now().Add(serverWriteTimeout)); err != nil {
			return err
		}

		if _, err := nb.WriteTo(sc.conn); err != nil {
			return err
		}

		if err := ctx.Err(); err != nil {
			return err
		}
	}
}

// wnotify notifies the writer of new buffers.
func (sc *serverConn) wnotify() {
	select {
	case sc.wbufC <- struct{}{}:
	default:
	}
}

// deliver is called by the router when a message is delivered to one of the conn's subscriptions.
func (sc *serverConn) deliver(id wire.ID, rm rmsg) {
	fh := wire.FrameHdr{
		Len:  uint32(16 + len(rm.Buf)),
		Type: wire.FPKG,
	}

	sc.mu.Lock()

	// frame header + id + errno + msg buf == a pkg frame
	prefix := binary.LittleEndian.AppendUint32(fh.Encode(nil), uint32(id))
	prefix = append(prefix, 0, 0, 0, 0)
	sc.wbufs = append(sc.wbufs, prefix, rm.Buf)

	sc.mu.Unlock()
	sc.wnotify()
}

// forget is called by the router when a subscription is done.
func (sc *serverConn) forget(id wire.ID) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	delete(sc.subs, id)
}

// reply is the delivery callback for the conn's reply wildcard subscription.
// Since the reply sub was created internally, it doesn't have an id.
// Instead, the request id for each reply is decrypted from the message path.
// If the path is malformed, unverifiable, or too old, the reply is dropped.
func (sc *serverConn) reply(_ wire.ID, rm rmsg) {
	b64, found := bytes.CutPrefix(rm.Msg.Path.data, sc.replyPrefix)
	if !found {
		return
	}

	buf, err := base64.RawURLEncoding.AppendDecode(nil, b64)
	if err != nil {
		return
	}

	nsz := sc.replyAEAD.NonceSize()
	if len(buf) < nsz {
		return
	}

	nonce := buf[:nsz]
	buf = buf[nsz:]
	payload, err := sc.replyAEAD.Open(nil, nonce, buf, sc.replyPrefix)
	if err != nil {
		return
	}

	if len(payload) != 12 {
		return
	}

	id := wire.ID(binary.LittleEndian.Uint32(payload))
	nsec := int64(binary.LittleEndian.Uint64(payload[4:]))
	exp := time.Unix(0, nsec)

	if time.Now().After(exp) {
		return
	}

	sc.deliver(id, rm)
}

// fail writes an err frame to the buffer and notifies the writer.
func (sc *serverConn) fail(id wire.ID, errno Errno) error {
	sc.mu.Lock()

	sc.wbufs = append(sc.wbufs, wire.AppendFrame(nil, wire.FERR,
		wire.ErrFrameBody{
			ID:    id,
			Errno: uint32(errno),
		}.Encode))

	sc.mu.Unlock()
	sc.wnotify()
	return nil
}

// handleSpecialRequest handles requests to the server-provided API.
// Currently the only API is "$conn/api/Flush", which writes an empty response.
func (sc *serverConn) handleSpecialRequest(path Path, id wire.ID, data []byte) error {
	switch path.String() {
	case "$conn/api/Flush":
		sc.mu.Lock()

		sc.wbufs = append(sc.wbufs, wire.AppendFrame(nil, wire.FPKG,
			wire.PkgFrameBody{
				ID: id,
			}.Encode))

		sc.mu.Unlock()
		sc.wnotify()

	default:
		return sc.fail(id, ENOENT)
	}

	return nil
}

// appendReplyPath generates and appends an encrypted reply path to b, returning the extended buffer.
// The path is in the form "@/$b64(rr.id)/$b64(sc.id)/$b64(encrypt(id, exp))",
// using the raw URL base64 encoding. The path expires after serverReplyPathTimeout.
//
// When a reply is received, the path is decrypted by [serverConn.reply]
// and verified before delivery.
func (sc *serverConn) appendReplyPath(b []byte, id wire.ID) []byte {
	b64 := base64.RawURLEncoding
	sc.replySetup.Do(func() {
		key := make([]byte, 32)
		rand.Read(key)

		// never returns err != nil
		// because key is a valid size
		block, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}

		// only returns err != nil in FIPS 140 mode
		// which seems like a future problem
		sc.replyAEAD, err = cipher.NewGCM(block)
		if err != nil {
			panic(err)
		}

		sc.replyPrefix = b64.AppendEncode([]byte("@/"), sc.cfg.Router.id[:])
		sc.replyPrefix = append(b64.AppendEncode(append(sc.replyPrefix, '/'), sc.id[:]), '/')
		sc.replyPrefix = sc.replyPrefix[:len(sc.replyPrefix):len(sc.replyPrefix)]

		sc.replySub = &rsub{
			Sel:     Sel{Path: Path{append(sc.replyPrefix, '*')}},
			Deliver: sc.reply,
		}

		sc.cfg.Router.swap(nil, sc.replySub)
	})

	exp := time.Now().Add(serverReplyPathTimeout)

	payload := make([]byte, 12)
	binary.LittleEndian.PutUint32(payload, uint32(id))
	binary.LittleEndian.PutUint64(payload[4:], uint64(exp.UnixNano()))

	nonce := make([]byte, sc.replyAEAD.NonceSize())
	rand.Read(nonce)

	enc := sc.replyAEAD.Seal(nonce, nonce, payload, sc.replyPrefix)
	return b64.AppendEncode(append(b, sc.replyPrefix...), enc)
}

// unroute is called after the conn is closed.
func (sc *serverConn) unroute() {
	var subs []*rsub
	for _, s := range sc.subs {
		subs = append(subs, s)
	}

	if sc.replySub != nil {
		subs = append(subs, sc.replySub)
	}

	if len(subs) > 0 {
		sc.cfg.Router.rm(subs)
	}
}

func (cfg ServerConfig) withDefaults() ServerConfig {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}

	if cfg.Router == nil {
		cfg.Router = NewRouter()
	}

	return cfg
}
