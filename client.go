package yat

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/jwt"

	yatv1 "yat.io/yat/internal/wire/yat/v1"
)

type Client struct {
	config ClientConfig
	conn   *grpc.ClientConn
	mc     yatv1.MsgServiceClient
}

type ClientConfig struct {
	// Logger is where the client writes logs.
	// Client logs are discarded by default.
	Logger *slog.Logger

	// TLSConfig configures the client's transport credentials.
	// If it is nil, the client uses a default TLS configuration.
	TLSConfig *tls.Config

	// GetCreds, if set, is called for each request.
	// The returned map is added to the request metadata.
	GetCreds CredsFunc
}

// A CredsFunc is called by the client to produce per-request credentials.
type CredsFunc func(ctx context.Context, requestURI ...string) (map[string]string, error)

// NewClient returns a new client for the given server and configuration.
// The client connects lazily and redials if the connection is broken.
func NewClient(server string, config ClientConfig) (*Client, error) {
	config = config.withDefaults()
	creds := credentials.NewTLS(config.TLSConfig)

	opts := []grpc.DialOption{
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
		grpc.WithTransportCredentials(creds),
	}

	if config.GetCreds != nil {
		opts = append(opts, grpc.WithPerRPCCredentials(credsFunc(config.GetCreds)))
	}

	conn, err := grpc.NewClient(server, opts...)
	if err != nil {
		return nil, err
	}

	mc := yatv1.NewMsgServiceClient(conn)

	c := &Client{
		config: config,
		conn:   conn,
		mc:     mc,
	}

	return c, nil
}

// Publish publishes m.
// It returns an error if m is invalid or rejected by the server.
func (c *Client) Publish(ctx context.Context, m Msg) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if c.isShutdown() {
		return net.ErrClosed
	}

	if err := validateOutboundMsg(m); err != nil {
		return err
	}

	req := &yatv1.PubRequest{
		Path:  m.Path.bytes(),
		Inbox: m.Inbox.bytes(),
		Data:  m.Data,
	}

	// FIX: transform some gRPC errors into our own client errors
	_, err := c.mc.Pub(ctx, req)
	return err
}

// NewPublisher returns a new publish stream.
// Use it to efficiently publish many messages.
//
// The returned stream must not be called concurrently.
func (c *Client) NewPublisher(ctx context.Context) (*PublishStream, error) {
	if c.isShutdown() {
		return nil, net.ErrClosed
	}

	ctx, cancel := ctxWithCancelCause(ctx)
	stream, err := c.mc.Mpub(ctx)
	if err != nil {
		return nil, err
	}

	p := &PublishStream{
		context: ctx,
		cancel:  cancel,
		stream:  stream,
		acks:    map[int64]chan *yatv1.MpubResponse{},
	}

	go p.recv()
	return p, nil
}

// NewEmitter returns a new emit stream.
// Use it to publish messages without waiting for the server.
//
// The returned stream must not be called concurrently.
func (c *Client) NewEmitter(ctx context.Context) (*EmitStream, error) {
	if c.isShutdown() {
		return nil, net.ErrClosed
	}

	ctx, cancel := ctxWithCancelCause(ctx)
	stream, err := c.mc.Emit(ctx)
	if err != nil {
		return nil, err
	}

	return &EmitStream{
		context: ctx,
		cancel:  cancel,
		stream:  stream,
	}, nil
}

func (c *Client) Post(ctx context.Context, req Req, f func(Res) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if f == nil {
		return errNilFunc
	}

	if c.isShutdown() {
		return net.ErrClosed
	}

	if err := validateOutboundReq(req); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	in := &yatv1.PostRequest{
		Path:  req.Path.bytes(),
		Data:  req.Data,
		Limit: new(int64(req.Limit)),
	}

	stream, err := c.mc.Post(ctx, in)
	if err != nil {
		return err
	}

	// did the stream end early?
	md, err := stream.Header()
	if err != nil {
		return err
	}

	// yes it did,
	// probably auth
	if md == nil {
		_, err := stream.Recv()
		return err
	}

	for {
		out, err := stream.Recv()
		if err == io.EOF {
			return nil
		}

		if err != nil {
			return err
		}

		var res Res
		err = func() error {
			inbox, err := parseMsgInboxFromServer(out.GetInbox())
			if err != nil {
				return err
			}

			res = Res{
				Inbox: inbox,
				Data:  out.GetData(),
			}

			return nil
		}()

		if err != nil {
			c.config.Logger.Error("drop invalid response", "error", err)
			continue
		}

		if err := f(res); err != nil {
			return err
		}
	}
}

// Subscribe arranges for f to be called in a new goroutine when a message matching sel is published.
// The given context controls the lifetime of the subscription.
func (c *Client) Subscribe(ctx context.Context, sel Sel, f func(context.Context, Msg)) (Sub, error) {
	return c.sub(ctx, sel, false, f)
}

func (c *Client) Handle(ctx context.Context, sel Sel, f func(ctx context.Context, path Path, in []byte) (out []byte)) (Sub, error) {
	if f == nil {
		return nil, errNilFunc
	}

	return c.sub(ctx, sel, true, func(ctx context.Context, m Msg) {
		if m.Inbox.IsZero() {
			return
		}

		data := f(ctx, m.Path, m.Data)

		om := Msg{
			Path: m.Inbox,
			Data: data,
		}

		// FIX: this is a pretty expensive way to respond
		// because Publish sends a new RPC for every response
		// instead, create a new emitter for the handler
		// or use a shared emitter for responses

		if err := c.Publish(ctx, om); err != nil {
			c.config.Logger.ErrorContext(ctx, "handler response failed",
				"error", err, "path", m.Path, "inbox", m.Inbox)
		}
	})
}

func (c *Client) sub(ctx context.Context, sel Sel, handler bool, f func(context.Context, Msg)) (Sub, error) {
	if err := validateOutboundSel(sel); err != nil {
		return nil, err
	}

	if f == nil {
		return nil, errNilFunc
	}

	if c.isShutdown() {
		return nil, net.ErrClosed
	}

	req := &yatv1.SubRequest{
		Path: sel.Path.bytes(),
	}

	if sel.Limit > 0 {
		req.Limit = new(int64(sel.Limit))
	}

	if handler {
		req.Flags = new(yatv1.SubFlags_SUB_FLAGS_HANDLER)
	}

	// FIX: transform some gRPC errors into our own client errors
	stream, err := c.mc.Sub(ctx, req)
	if err != nil {
		return nil, err
	}

	// did the stream end early?
	md, err := stream.Header()
	if err != nil {
		return nil, err
	}

	// yes it did,
	// probably auth
	if md == nil {
		_, err := stream.Recv()
		return nil, err
	}

	sub := csub{make(chan struct{})}
	wg := &sync.WaitGroup{}

	go func() {
		defer close(sub.C)
		defer wg.Wait()

		for {
			res, err := stream.Recv()
			if err != nil {
				return
			}

			var m Msg
			err = func() error {
				path, err := parseMsgPath(res.GetPath())
				if err != nil {
					return err
				}

				inbox, err := parseMsgInboxFromServer(res.GetInbox())
				if err != nil {
					return err
				}

				id, err := uuid.FromBytes(res.GetUuid())
				if err != nil {
					return err
				}

				m = Msg{
					Path:  path,
					Inbox: inbox,
					Data:  res.GetData(),
					uuid:  id,
				}

				return nil
			}()

			if err != nil {
				c.config.Logger.Error("drop invalid message", "error", err)
				continue
			}

			wg.Go(func() { f(ctx, m) })
		}
	}()

	return sub, nil
}

// Close stops all subscriptions and closes the client.
func (c *Client) Close() error {
	return c.conn.Close()
}

func (c *Client) isShutdown() bool {
	return c.conn.GetState() == connectivity.Shutdown
}

// BearerToken returns a generator that adds an authorization header containing the given JWT.
func BearerToken(token string) CredsFunc {
	return func(context.Context, ...string) (map[string]string, error) {
		return map[string]string{
			"authorization": "Bearer " + token,
		}, nil
	}
}

// TokenFile returns a generator backed by the named file,
// which must contain a signed JWT with an "exp" claim.
func TokenFile(name string) CredsFunc {
	if name == "" {
		return func(ctx context.Context, uri ...string) (map[string]string, error) {
			return nil, errors.New("empty token file path")
		}
	}

	creds, _ := jwt.NewTokenFileCallCredentials(name)
	return creds.GetRequestMetadata
}

// A PublishStream efficiently publishes a stream of messages.
// It is not safe for concurrent use.
type PublishStream struct {
	context context.Context
	cancel  context.CancelCauseFunc
	stream  grpc.BidiStreamingClient[yatv1.MpubRequest, yatv1.MpubResponse]

	mu   sync.Mutex
	ackn int64
	acks map[int64]chan *yatv1.MpubResponse
}

// Publish publishes m.
// It returns an error if m is invalid or rejected by the server.
func (p *PublishStream) Publish(ctx context.Context, m Msg) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if err := context.Cause(p.context); err != nil {
		return err
	}

	if err := validateOutboundMsg(m); err != nil {
		return err
	}

	resC := make(chan *yatv1.MpubResponse, 1)

	p.mu.Lock()
	p.ackn++
	ack := p.ackn
	p.acks[ack] = resC
	p.mu.Unlock()

	defer func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		delete(p.acks, ack)
	}()

	err := p.stream.Send(&yatv1.MpubRequest{
		Ack:   &ack,
		Path:  m.Path.bytes(),
		Inbox: m.Inbox.bytes(),
		Data:  m.Data,
	})

	if err != nil {
		return err
	}

	select {
	case <-ctx.Done():
		return ctx.Err()

	case <-p.context.Done():
		return context.Cause(p.context)

	case res := <-resC:
		// FIX: translate some codes to our own errors
		// otherwise a status.Error is fine
		c := codes.Code(res.GetStatus())
		switch c {
		case codes.OK:
			return nil

		default:
			return errors.New(c.String())
		}
	}
}

// Close closes the stream.
func (p *PublishStream) Close() error {
	// FIX: all errors must be reconsidered
	p.cancel(errors.New("publisher closed"))
	return nil
}

func (p *PublishStream) recv() {
	for {
		res, err := p.stream.Recv()
		if err != nil && err != p.context.Err() {
			p.cancel(err)
			return
		}

		p.mu.Lock()
		ack := res.GetAck()
		resC := p.acks[ack]
		delete(p.acks, ack)
		p.mu.Unlock()

		if resC == nil {
			continue
		}

		select {
		case resC <- res:
		default:
		}
	}
}

// EmitStream publishes a stream of messages as quickly as possible.
type EmitStream struct {
	context context.Context
	cancel  context.CancelCauseFunc
	stream  grpc.ClientStreamingClient[yatv1.EmitRequest, yatv1.EmitResponse]
}

// Emit publishes m without waiting for the server to respond.
func (e *EmitStream) Emit(m Msg) error {
	if err := context.Cause(e.context); err != nil {
		return err
	}

	if err := validateOutboundMsg(m); err != nil {
		return err
	}

	req := &yatv1.EmitRequest{
		Path:  m.Path.bytes(),
		Inbox: m.Inbox.bytes(),
		Data:  m.Data,
	}

	if err := e.stream.Send(req); err != nil {
		e.cancel(err)
		return err
	}

	return nil
}

func (e *EmitStream) Close() error {
	if err := context.Cause(e.context); err != nil {
		return err
	}

	_, err := e.stream.CloseAndRecv()
	if err != nil {
		e.cancel(err)
		return err
	}

	// FIX: all errors must be reconsidered
	e.cancel(errors.New("emitter closed"))
	return nil
}

func (c ClientConfig) withDefaults() ClientConfig {
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}

	if c.TLSConfig == nil {
		c.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
		}
	}

	return c
}

// csub implements [Sub] in terms of a channel,
// like a very simple [context.Context].
type csub struct {
	C chan struct{}
}

func (s csub) Done() <-chan struct{} {
	return s.C
}

// credsFunc implements [credentials.PerRPCCredentials] in terms of CredsFunc
// to avoid exporting those methods as part of the yat API.
// Also because we always require transport security.
type credsFunc CredsFunc

func (f credsFunc) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return f(ctx, uri...)
}

func (f credsFunc) RequireTransportSecurity() bool {
	return true
}

// ctxWithCancelCause silences a (usually useful) Go warning about not calling cancel.
func ctxWithCancelCause(parent context.Context) (context.Context, func(error)) {
	return context.WithCancelCause(parent)
}
