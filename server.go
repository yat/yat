package yat

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"yat.io/yat/internal/web"

	yatv1 "yat.io/yat/internal/wire/yat/v1"
)

type Server struct {
	cfg ServerConfig
	mux *http.ServeMux
}

type ServerConfig struct {
	// Logger is where the server writes logs.
	// Server logs are discarded by default.
	Logger *slog.Logger

	// Router is how the server delivers messages.
	// An internal router is created by default.
	Router *Router

	// Rules decide which client operations are allowed.
	// All operations are denied by default.
	Rules *RuleSet

	// URL is the server's https address.
	// If it is nil, only RPC routes are enabled.
	URL *url.URL
}

func NewServer(cfg ServerConfig) (*Server, error) {
	cfg, err := cfg.validate()
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()

	s := &Server{
		cfg: cfg,
		mux: mux,
	}

	if cfg.URL != nil {
		static, _ := fs.Sub(web.FS, "static")
		mux.Handle("/", http.FileServerFS(static))
	}

	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case yatv1.MsgService_Pub_FullMethodName:
		s.serveGRPC(w, r, s.handleMsgPub)

	case yatv1.MsgService_Mpub_FullMethodName:
		s.serveGRPC(w, r, s.handleMsgMpub)

	case yatv1.MsgService_Emit_FullMethodName:
		s.serveGRPC(w, r, s.handleMsgEmit)

	case yatv1.MsgService_Post_FullMethodName:
		s.serveGRPC(w, r, s.handleMsgPost)

	case yatv1.MsgService_Sub_FullMethodName:
		s.serveGRPC(w, r, s.handleMsgSub)

	default:
		s.mux.ServeHTTP(w, r)
	}
}

// Config returns the server configuration, including default values.
func (s *Server) Config() ServerConfig {
	return s.cfg
}

type grpcHandlerFunc func(logger *slog.Logger, allow func(Path, Action) bool, w http.ResponseWriter, r *http.Request) error

// serveGRPC serves (barely) gRPC-compatible responses.
func (s *Server) serveGRPC(w http.ResponseWriter, r *http.Request, handle grpcHandlerFunc) {
	if r.ProtoMajor != 2 {
		http.Error(w, "http/2 is required",
			http.StatusHTTPVersionNotSupported)

		return
	}

	if r.Method != http.MethodPost {
		w.Header().Set("allow", http.MethodPost)
		http.Error(w, "method not allowed",
			http.StatusMethodNotAllowed)

		return
	}

	if !isGRPC(r) {
		http.Error(w, "unsupported content-type",
			http.StatusUnsupportedMediaType)

		return
	}

	if _, flushable := w.(http.Flusher); !flushable {
		http.Error(w, "unflushable",
			http.StatusInternalServerError)

		return
	}

	if to := r.Header.Get("grpc-timeout"); to != "" {
		d, err := grpcDecodeTimeout(to)
		if err != nil {
			http.Error(w, "bad grpc-timeout",
				http.StatusBadRequest)

			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), d)
		defer cancel()

		r = r.WithContext(ctx)
	}

	var caller Principal
	if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 {
		if chain := r.TLS.VerifiedChains[0]; len(chain) > 0 {
			caller.Cert = chain[0]
		}
	}

	if token, ok := strings.CutPrefix(r.Header.Get("authorization"), "Bearer "); ok {
		claims, err := s.cfg.Rules.VerifyToken(r.Context(), token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		caller.Claims = claims
	}

	var largs []any

	if caller.Cert != nil {
		largs = append(largs,
			"cert.iss", caller.Cert.Issuer.CommonName,
			"cert.sub", caller.Cert.Subject.String(),
		)

		if len(caller.Cert.URIs) > 0 {
			var uris []string
			for _, u := range caller.Cert.URIs {
				uris = append(uris, u.String())
			}

			largs = append(largs, "cert.uris", uris)
		}
	}

	if caller.Claims != nil {
		largs = append(largs,
			"claims.iss", caller.Claims.claims["iss"],
			"claims.sub", caller.Claims.claims["sub"])
	}

	logger := s.cfg.Logger.With("remote", r.RemoteAddr)
	logger.DebugContext(r.Context(), "caller identified", largs...)

	w.Header().Set("content-type",
		"application/grpc")

	w.Header().Add("trailer",
		"grpc-status,grpc-message")

	allow, err := s.cfg.Rules.Compile(caller)

	if err != nil {
		logger.ErrorContext(r.Context(), "rule compilation failed", "error", err)
		err = status.Error(codes.Internal, "malformed rule set")
	}

	if logger.Enabled(r.Context(), slog.LevelDebug) {
		wrapped := allow
		allow = func(p Path, a Action) bool {
			ok := wrapped(p, a)
			if !ok {
				logger.DebugContext(r.Context(),
					"not allowed", "path", p, "action", a)
			}

			return ok
		}
	}

	if err == nil {
		err = handle(logger, allow, w, r)
	}

	if he, ok := err.(httpError); ok {
		http.Error(w, he.Message, he.Status)
		return
	}

	if st := status.FromContextError(err); st != nil && st.Code() != codes.Unknown {
		err = st.Err()
	}

	st, _ := status.FromError(err)
	code := st.Code()

	w.Header().Set("grpc-status",
		strconv.FormatUint(uint64(code), 10))

	if msg := st.Message(); msg != "" {
		w.Header().Set("grpc-message", msg)
	}
}

func (s *Server) handleMsgPub(logger *slog.Logger, allow func(Path, Action) bool, w http.ResponseWriter, r *http.Request) error {
	_, frm, err := readMsgPubFrm(r.Body)
	if err != nil {
		return err
	}

	if err := validateEOF(r.Body); err != nil {
		return err
	}

	frm, fields, err := parseMsgPubFrm(frm)
	if err != nil {
		return err
	}

	m, err := fields.Parse()
	if err != nil {
		return err
	}

	if ok := s.cfg.Router.validPostbox(m.Path) || allow(m.Path, ActionPub); !ok {
		return rpcErrPerms
	}

	if !m.Inbox.IsZero() && !allow(m.Inbox, ActionSub) {
		return rpcErrPerms
	}

	s.deliver(m, frm)

	// an empty PubResponse
	_, err = w.Write([]byte{0, 0, 0, 0, 0})
	return err
}

func (s *Server) handleMsgMpub(logger *slog.Logger, allow func(Path, Action) bool, w http.ResponseWriter, r *http.Request) error {
	flusher := w.(http.Flusher)

	for {
		_, frm, err := readMsgPubFrm(r.Body)
		if err == io.EOF {
			return nil
		}

		if err != nil {
			return err
		}

		frm, fields, err := parseMsgPubFrm(frm)
		if err != nil {
			return err
		}

		m, err := fields.Parse()
		if err == nil && !s.cfg.Router.validPostbox(m.Path) && !allow(m.Path, ActionPub) {
			err = rpcErrPerms
		}

		if err == nil && !m.Inbox.IsZero() && !allow(m.Inbox, ActionSub) {
			err = rpcErrPerms
		}

		if err == nil {
			s.deliver(m, frm)
		}

		st, _ := status.FromError(err)
		_, err = w.Write(appendGRPCFrm(nil, func(b []byte) []byte {
			b = protowire.AppendTag(b, ackField, protowire.VarintType)
			b = protowire.AppendVarint(b, fields.Ack)

			if code := st.Code(); code != codes.OK {
				b = protowire.AppendTag(b, statusField, protowire.VarintType)
				b = protowire.AppendVarint(b, uint64(code))
			}

			return b
		}))
		if err != nil {
			return err
		}

		flusher.Flush()
	}
}

func (s *Server) handleMsgEmit(logger *slog.Logger, allow func(Path, Action) bool, w http.ResponseWriter, r *http.Request) error {
	for {
		_, frm, err := readMsgPubFrm(r.Body)
		if err == io.EOF {
			// an empty EmitResponse
			_, err = w.Write([]byte{0, 0, 0, 0, 0})
			return err
		}

		if err != nil {
			return err
		}

		frm, fields, err := parseMsgPubFrm(frm)
		if err != nil {
			return err
		}

		m, err := fields.Parse()
		if err != nil {
			return err
		}

		if !s.cfg.Router.validPostbox(m.Path) && !allow(m.Path, ActionPub) {
			return rpcErrPerms
		}

		if !m.Inbox.IsZero() && !allow(m.Inbox, ActionSub) {
			return rpcErrPerms
		}

		s.deliver(m, frm)
	}
}

// deliver prepares and delivers a message and its backing frame.
// A uuid field is generated for m and append to frm before delivery.
func (s *Server) deliver(m Msg, frm []byte) {
	if ee := s.cfg.Router.route(m); len(ee) > 0 {
		m.uuid, frm = addUUIDField(frm)
		s.cfg.Router.deliver(ee, rmsg{m, frm})
	}
}

func (s *Server) handleMsgPost(logger *slog.Logger, allow func(Path, Action) bool, w http.ResponseWriter, r *http.Request) error {
	_, frm, err := readMsgPubFrm(r.Body)
	if err != nil {
		return err
	}

	if err := validateEOF(r.Body); err != nil {
		return err
	}

	frm, fields, err := parseMsgPostFrm(frm)
	if err != nil {
		return err
	}

	path, data, err := fields.Parse()
	if err != nil {
		return err
	}

	limit, err := parseLimit(fields.Limit)
	if err != nil {
		return err
	}

	if !allow(path, ActionPub) {
		return rpcErrPerms
	}

	m := Msg{
		Path: path,
		Data: data,
	}

	m.Inbox, frm = s.addPostboxField(frm)

	ee := s.cfg.Router.route(m)
	hnd := slices.ContainsFunc(ee, (*rent).IsHandler)

	if len(ee) == 0 || !hnd {
		return rpcErrNoHandler
	}

	m.uuid, frm = addUUIDField(frm)

	sel := Sel{
		Path:  m.Inbox,
		Limit: limit,
	}

	sb := &sbuf{
		bufC:  make(chan struct{}, 1),
		doneC: make(chan struct{}),
	}

	rs := rsub{
		Sel: sel,
	}

	// subscribe to the postbox
	e := s.cfg.Router.ins(rs, sb.Deliver)
	defer s.cfg.Router.del(e)

	// publish the post
	s.cfg.Router.deliver(ee, rmsg{m, frm})

	// and stream responses
	return sb.Flush(w, r)
}

// addPostboxField adds an inbox proto field containing a router postbox to the frame.
// If frm doesn't have capacity for the new field, addPostboxField panics.
func (s *Server) addPostboxField(frm []byte) (inbox Path, ext []byte) {
	_ = frm[:len(frm)+postboxFieldLen]
	inbox = s.cfg.Router.newPostbox()
	frm = protowire.AppendTag(frm, inboxField, protowire.BytesType)
	frm = protowire.AppendString(frm, inbox.s)
	binary.BigEndian.PutUint32(frm[1:], uint32(len(frm)-grpcFrmHdrLen))
	return inbox, frm
}

func (s *Server) handleMsgSub(logger *slog.Logger, allow func(Path, Action) bool, w http.ResponseWriter, r *http.Request) error {
	hdr, err := readGRPCFrmHdr(r.Body)
	if err != nil {
		return err
	}

	frm := make([]byte, grpcFrmHdrLen+hdr.BodyLen())
	if _, err := io.ReadFull(r.Body, frm[grpcFrmHdrLen:]); err != nil {
		return err
	}

	if err := validateEOF(r.Body); err != nil {
		return err
	}

	var req yatv1.SubRequest
	if err := proto.Unmarshal(frm[grpcFrmHdrLen:], &req); err != nil {
		return err
	}

	path, err := parseSelPath(req.GetPath())
	if err != nil {
		return err
	}

	limit, err := parseLimit(req.GetLimit())
	if err != nil {
		return err
	}

	sel := Sel{
		Path:  path,
		Limit: limit,
	}

	if !allow(sel.Path, ActionSub) {
		return httpErrPerms
	}

	sb := &sbuf{
		bufC:  make(chan struct{}, 1),
		doneC: make(chan struct{}),
	}

	rs := rsub{
		Sel:   sel,
		Flags: req.GetFlags(),
	}

	e := s.cfg.Router.ins(rs, sb.Deliver)
	defer s.cfg.Router.del(e)
	return sb.Flush(w, r)
}

// validate checks the config after setting default values.
func (c ServerConfig) validate() (valid ServerConfig, err error) {
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}

	if c.Router == nil {
		c.Router = NewRouter()
	}

	if c.Rules == nil {
		c.Rules = &RuleSet{}
	}

	if c.URL != nil && c.URL.Scheme != "https" {
		return ServerConfig{}, fmt.Errorf("server URL scheme (%s) is not https", c.URL.Scheme)
	}

	return c, nil
}

// sbuf is a subscription delivery buffer.
// Deliver adds deliveries to a buffer list
// and Flush flushes them.
type sbuf struct {
	wg     sync.WaitGroup
	mu     sync.Mutex
	bufs   net.Buffers
	nbytes int64

	bufC  chan struct{}
	doneC chan struct{}
}

func (sb *sbuf) Deliver(rm rmsg, final bool) {
	sb.wg.Add(1)
	defer sb.wg.Done()

	if final {
		close(sb.doneC)
	}

	sb.mu.Lock()

	flen := int64(len(rm.frm))
	if sb.nbytes+flen > maxSubBufLen {
		sb.mu.Unlock()
		return
	}

	sb.bufs = append(sb.bufs, rm.frm)
	sb.nbytes += flen

	sb.mu.Unlock()

	select {
	case sb.bufC <- struct{}{}:
	default:
	}
}

func (sb *sbuf) Flush(w io.Writer, r *http.Request) error {
	flusher := w.(http.Flusher)
	flusher.Flush() // headers

	var done bool
	var err error

	for {
		select {
		case <-r.Context().Done():
			err = r.Context().Err()

		case <-sb.doneC:
			sb.wg.Wait()
			done = true

		case <-sb.bufC:
			// flush
		}

		sb.mu.Lock()
		bb := sb.bufs
		sb.bufs = nil
		sb.nbytes = 0
		sb.mu.Unlock()

		if len(bb) > 0 {
			if _, err = bb.WriteTo(w); err == nil {
				flusher.Flush()
			}
		}

		if err != nil {
			return err
		}

		if done {
			return nil
		}
	}
}

func isGRPC(r *http.Request) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("content-type"))
	if err != nil {
		return false
	}

	mt = strings.ToLower(mt)
	return mt == "application/grpc" ||
		strings.HasPrefix(mt, "application/grpc+proto")
}

// addUUIDField adds a uuid proto field containing a raw UUIDv7 to the frame.
// If frm doesn't have capacity for the new field, addUUIDField panics.
func addUUIDField(frm []byte) (id uuid.UUID, ext []byte) {
	_ = frm[:len(frm)+uuidFieldLen]
	id = uuid.Must(uuid.NewV7())
	frm = protowire.AppendTag(frm, uuidField, protowire.BytesType)
	frm = protowire.AppendBytes(frm, id[:])
	binary.BigEndian.PutUint32(frm[1:], uint32(len(frm)-grpcFrmHdrLen))
	return id, frm
}
