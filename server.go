package yat

import (
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	msgv1 "yat.io/yat/internal/wire/msg/v1"
)

type Server struct {
	router *Router
	config ServerConfig
}

type ServerConfig struct {
	Logger *slog.Logger
	Rules  *RuleSet
}

func NewServer(router *Router, config ServerConfig) (*Server, error) {
	config = config.withDefaults()

	if router == nil {
		return nil, errors.New("nil router")
	}

	s := &Server{
		router: router,
		config: config,
	}

	return s, nil
}

// ServeHTTP serves (barely) gRPC-compatible API endpoints.
// It requires all requests to be HTTP/2 POSTs with the application/grpc content-type.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

	if r.Header.Get("content-type") != "application/grpc" {
		http.Error(w, "unsupported content-type",
			http.StatusUnsupportedMediaType)

		return
	}

	if _, flushable := w.(http.Flusher); !flushable {
		http.Error(w, "unflushable",
			http.StatusInternalServerError)

		return
	}

	var handle func(allow func(Path, Action) bool, w http.ResponseWriter, r *http.Request) error

	switch r.URL.Path {
	case msgv1.MsgService_Pub_FullMethodName:
		handle = s.handleMsgPub

	case msgv1.MsgService_Mpub_FullMethodName:
		handle = s.handleMsgMpub

	case msgv1.MsgService_Emit_FullMethodName:
		handle = s.handleMsgEmit

	case msgv1.MsgService_Post_FullMethodName:
		handle = s.handleMsgPost

	case msgv1.MsgService_Sub_FullMethodName:
		handle = s.handleMsgSub

	default:
		http.NotFound(w, r)
		return
	}

	var caller Principal
	if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 {
		if chain := r.TLS.VerifiedChains[0]; len(chain) > 0 {
			caller.Cert = chain[0]
		}
	}

	if token, ok := strings.CutPrefix(r.Header.Get("authorization"), "Bearer "); ok {
		claims, err := s.config.Rules.VerifyToken(r.Context(), token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		caller.Claims = claims
	}

	w.Header().Set("content-type",
		"application/grpc")

	w.Header().Add("trailer",
		"grpc-status,grpc-message")

	allow, err := s.config.Rules.Compile(caller)

	if err != nil {
		s.config.Logger.ErrorContext(r.Context(), "rule compilation failed", "error", err)
		err = status.Error(codes.Internal, "malformed rule set")
	}

	if err == nil {
		err = handle(allow, w, r)
	}

	if he, ok := err.(httpError); ok {
		http.Error(w, he.Message, he.Status)
		return
	}

	st, _ := status.FromError(err)
	code := st.Code()

	w.Header().Set("grpc-status",
		strconv.FormatUint(uint64(code), 10))

	if msg := st.Message(); msg != "" {
		w.Header().Set("grpc-message", msg)
	}
}

func (s *Server) handleMsgPub(allow func(Path, Action) bool, w http.ResponseWriter, r *http.Request) error {
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

	if !s.router.validPostbox(m.Path) && !allow(m.Path, ActionPub) {
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

func (s *Server) handleMsgMpub(allow func(Path, Action) bool, w http.ResponseWriter, r *http.Request) error {
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
		if err == nil && !s.router.validPostbox(m.Path) && !allow(m.Path, ActionPub) {
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

func (s *Server) handleMsgEmit(allow func(Path, Action) bool, w http.ResponseWriter, r *http.Request) error {
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

		if !s.router.validPostbox(m.Path) && !allow(m.Path, ActionPub) {
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
	if ee := s.router.route(m); len(ee) > 0 {
		m.uuid, frm = addUUIDField(frm)
		s.router.deliver(ee, rmsg{m, frm})
	}
}

func (s *Server) handleMsgPost(allow func(Path, Action) bool, w http.ResponseWriter, r *http.Request) error {
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

	ee := s.router.route(m)
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
	e := s.router.ins(rs, sb.Deliver)
	defer s.router.del(e)

	// publish the post
	s.router.deliver(ee, rmsg{m, frm})

	// and stream responses
	return sb.Flush(w, r)
}

// addPostboxField adds an inbox proto field containing a router postbox to the frame.
// If frm doesn't have capacity for the new field, addPostboxField panics.
func (s *Server) addPostboxField(frm []byte) (inbox Path, ext []byte) {
	_ = frm[:len(frm)+postboxFieldLen]
	inbox = s.router.newPostbox()
	frm = protowire.AppendTag(frm, inboxField, protowire.BytesType)
	frm = protowire.AppendString(frm, inbox.s)
	binary.BigEndian.PutUint32(frm[1:], uint32(len(frm)-grpcFrmHdrLen))
	return inbox, frm
}

func (s *Server) handleMsgSub(allow func(Path, Action) bool, w http.ResponseWriter, r *http.Request) error {
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

	var req msgv1.SubRequest
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

	e := s.router.ins(rs, sb.Deliver)
	defer s.router.del(e)
	return sb.Flush(w, r)
}

func (c ServerConfig) withDefaults() ServerConfig {
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}

	if c.Rules == nil {
		c.Rules = &RuleSet{}
	}

	return c
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
