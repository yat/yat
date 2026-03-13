//go:build !human

// Integration-first generated tests:
// Keep this suite in package yat_test and exercise behavior through the public
// API using real Client/Server/Router interactions, raw protocol peers, and
// real TLS handshakes where needed. Do not add package yat internal tests,
// stub clients/servers/connections, or production-code changes just to raise
// coverage unless there is a strong, explicit justification.

package yat_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"yat.io/yat"
	"yat.io/yat/pkigen"
	"yat.io/yat/wire"
)

const (
	giFrameHdrLen = 4

	giPubFrameType   = 2
	giSubFrameType   = 4
	giUnsubFrameType = 5
	giMsgFrameType   = 16

	giNumField   = 1
	giPathField  = 2
	giDataField  = 3
	giInboxField = 4

	giMaxDataLen = 8 << 20

	giMsgTimeout   = 2 * time.Second
	giNoMsgTimeout = 75 * time.Millisecond
	giErrLongData  = "long data"
)

func TestGenIntegrationSurfaceValidation(t *testing.T) {
	if _, err := yat.NewClient(nil, yat.ClientConfig{}); err == nil {
		t.Fatal("nil dial func was accepted")
	}

	if _, err := yat.NewServer(nil, yat.ServerConfig{}); err == nil {
		t.Fatal("nil router was accepted")
	}

	if !yat.NewPath("topic/*").IsWild() {
		t.Fatal("wild path not reported as wild")
	}
	if yat.NewPath("topic/a").IsWild() {
		t.Fatal("literal path reported as wild")
	}

	validRules := []yat.Rule{
		{
			Grants: []yat.Grant{{
				Path:    yat.NewPath("a/**"),
				Actions: []yat.Action{yat.ActionSub},
			}},
		},
		{
			SPIFFE: &yat.SPIFFECond{
				Domain: "trust-domain",
				Path:   yat.NewPath("work/*"),
			},
			Grants: []yat.Grant{{
				Path:    yat.NewPath("b/**"),
				Actions: []yat.Action{yat.ActionPub, yat.ActionSub},
			}},
		},
	}
	if _, err := yat.NewRuleSet(validRules); err != nil {
		t.Fatal(err)
	}

	ruleErrors := []struct {
		name  string
		rules []yat.Rule
	}{
		{
			name: "empty spiffe domain",
			rules: []yat.Rule{{
				SPIFFE: &yat.SPIFFECond{},
				Grants: []yat.Grant{{
					Path:    yat.NewPath("path"),
					Actions: []yat.Action{yat.ActionPub},
				}},
			}},
		},
		{
			name: "invalid spiffe domain",
			rules: []yat.Rule{{
				SPIFFE: &yat.SPIFFECond{Domain: "Trust-Domain"},
				Grants: []yat.Grant{{
					Path:    yat.NewPath("path"),
					Actions: []yat.Action{yat.ActionPub},
				}},
			}},
		},
		{
			name:  "empty grants",
			rules: []yat.Rule{{}},
		},
		{
			name: "empty grant path",
			rules: []yat.Rule{{
				Grants: []yat.Grant{{Actions: []yat.Action{yat.ActionPub}}},
			}},
		},
		{
			name: "empty grant actions",
			rules: []yat.Rule{{
				Grants: []yat.Grant{{Path: yat.NewPath("path")}},
			}},
		},
		{
			name: "invalid grant action",
			rules: []yat.Rule{{
				Grants: []yat.Grant{{
					Path:    yat.NewPath("path"),
					Actions: []yat.Action{"delete"},
				}},
			}},
		},
	}

	for _, tc := range ruleErrors {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := yat.NewRuleSet(tc.rules); err == nil {
				t.Fatal("expected NewRuleSet error")
			}
		})
	}

	allow := yat.AllowAll().Compile(yat.Principal{})
	if !allow(yat.NewPath("pub"), yat.ActionPub) {
		t.Fatal("AllowAll denied pub")
	}
	if !allow(yat.NewPath("sub"), yat.ActionSub) {
		t.Fatal("AllowAll denied sub")
	}

	compiledRules := []yat.Rule{{
		Grants: []yat.Grant{{
			Path:    yat.NewPath("a"),
			Actions: []yat.Action{yat.ActionPub},
		}},
	}}
	rs, err := yat.NewRuleSet(compiledRules)
	if err != nil {
		t.Fatal(err)
	}

	allowCompiled := rs.Compile(yat.Principal{})
	compiledRules[0].Grants[0].Path = yat.NewPath("mutated")
	compiledRules[0].Grants[0].Actions[0] = yat.ActionSub

	if !allowCompiled(yat.NewPath("a"), yat.ActionPub) {
		t.Fatal("compiled rules changed after input mutation")
	}
	if allowCompiled(yat.NewPath("a"), yat.ActionSub) {
		t.Fatal("unexpected compiled action")
	}

	rr := yat.NewRouter()
	routerSub, err := rr.Subscribe(yat.Sel{Path: yat.NewPath("router/done")}, func(context.Context, yat.Msg) {})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-routerSub.Done():
		t.Fatal("router sub done closed early")
	default:
	}
	routerSub.Cancel()
	select {
	case <-routerSub.Done():
	default:
		t.Fatal("router sub done did not close")
	}

	c, err := yat.NewClient(func(context.Context) (net.Conn, error) {
		return nil, errors.New("dial failed")
	}, yat.ClientConfig{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = c.Close()
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.Publish(ctx, yat.Msg{Path: yat.NewPath("path")}); err != ctx.Err() {
		t.Fatalf("publish: %v != %v", err, ctx.Err())
	}

	msgErrors := []yat.Msg{
		{},
		{Path: yat.NewPath("*")},
		{Path: yat.NewPath("path"), Inbox: yat.NewPath("*")},
	}
	for _, msg := range msgErrors {
		if err := c.Publish(context.Background(), msg); err == nil {
			t.Fatalf("expected publish error for %#v", msg)
		}
	}

	tooLong := make([]byte, giMaxDataLen+1)
	if err := c.Publish(context.Background(), yat.Msg{Path: yat.NewPath("path"), Data: tooLong}); err == nil || err.Error() != giErrLongData {
		t.Fatalf("publish long data: %v", err)
	}

	if _, err := c.Subscribe(yat.Sel{}, func(context.Context, yat.Msg) {}); err == nil {
		t.Fatal("zero selector was accepted")
	}
	if _, err := c.Subscribe(yat.Sel{Path: yat.NewPath("path"), Limit: -1}, func(context.Context, yat.Msg) {}); err == nil {
		t.Fatal("negative limit was accepted")
	}
	if _, err := c.Subscribe(yat.Sel{Path: yat.NewPath("path"), Limit: yat.MaxLimit + 1}, func(context.Context, yat.Msg) {}); err == nil {
		t.Fatal("oversize limit was accepted")
	}
	if _, err := c.Subscribe(yat.Sel{Path: yat.NewPath("path")}, nil); err == nil {
		t.Fatal("nil callback was accepted")
	}

	sub, err := c.Subscribe(yat.Sel{Path: yat.NewPath("close/me")}, func(context.Context, yat.Msg) {})
	if err != nil {
		t.Fatal(err)
	}

	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case <-sub.Done():
	default:
		t.Fatal("sub done was not closed by client close")
	}

	if err := c.Close(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("close: %v", err)
	}
	if err := c.Publish(context.Background(), yat.Msg{Path: yat.NewPath("path")}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("publish after close: %v", err)
	}
	if _, err := c.Subscribe(yat.Sel{Path: yat.NewPath("path")}, func(context.Context, yat.Msg) {}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("subscribe after close: %v", err)
	}
}

func TestGenIntegrationClientProtocolFrames(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dialer := giNewPeerDialer()
		c, err := yat.NewClient(dialer.Dial, yat.ClientConfig{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			dialer.Close()
			_ = c.Close()
		})

		peer := dialer.Next(t)
		t.Cleanup(func() {
			_ = peer.Close()
		})

		sub, err := c.Subscribe(yat.Sel{
			Path:  yat.NewPath("jobs"),
			Group: yat.NewGroup("workers"),
			Limit: 5,
		}, func(context.Context, yat.Msg) {})
		if err != nil {
			t.Fatal(err)
		}

		typ, body := giReadAppFrame(t, peer, giMsgTimeout)
		if typ != giSubFrameType {
			t.Fatalf("frame type: %d != %d", typ, giSubFrameType)
		}

		var sf wire.SubFrame
		if err := proto.Unmarshal(body, &sf); err != nil {
			t.Fatal(err)
		}
		if sf.GetNum() != 1 {
			t.Fatalf("sub num: %d != %d", sf.GetNum(), 1)
		}
		if got := string(sf.GetPath()); got != "jobs" {
			t.Fatalf("sub path: %q != %q", got, "jobs")
		}
		if got := string(sf.GetGroup()); got != "workers" {
			t.Fatalf("sub group: %q != %q", got, "workers")
		}
		if sf.GetLimit() != 5 {
			t.Fatalf("sub limit: %d != %d", sf.GetLimit(), 5)
		}

		if err := c.Publish(context.Background(), yat.Msg{
			Path:  yat.NewPath("jobs"),
			Data:  []byte("payload"),
			Inbox: yat.NewPath("reply"),
		}); err != nil {
			t.Fatal(err)
		}

		typ, body = giReadAppFrame(t, peer, giMsgTimeout)
		if typ != giPubFrameType {
			t.Fatalf("frame type: %d != %d", typ, giPubFrameType)
		}

		num, msg := giDecodeSharedFields(t, body)
		if num != 0 {
			t.Fatalf("pub num: %d != 0", num)
		}
		giAssertMsg(t, msg, "jobs", []byte("payload"), "reply")

		sub.Cancel()
		select {
		case <-sub.Done():
		default:
			t.Fatal("cancel did not close sub done")
		}

		typ, body = giReadAppFrame(t, peer, giMsgTimeout)
		if typ != giUnsubFrameType {
			t.Fatalf("frame type: %d != %d", typ, giUnsubFrameType)
		}

		var uf wire.UnsubFrame
		if err := proto.Unmarshal(body, &uf); err != nil {
			t.Fatal(err)
		}
		if uf.GetNum() != 1 {
			t.Fatalf("unsub num: %d != %d", uf.GetNum(), 1)
		}

		synctest.Wait()
		time.Sleep(1 * time.Second)
		synctest.Wait()

		typ, body = giReadFrame(t, peer, giMsgTimeout)
		if typ != 0 || len(body) != 0 {
			t.Fatalf("keepalive: type=%d body=%x", typ, body)
		}
	})
}

func TestGenIntegrationClientProtocolInboundAndReconnect(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dialer := giNewPeerDialer()
		c, err := yat.NewClient(dialer.Dial, yat.ClientConfig{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			dialer.Close()
			_ = c.Close()
		})

		msgC, sub := giMustSubscribeClient(t, c, yat.Sel{Path: yat.NewPath("topic")})
		t.Cleanup(sub.Cancel)

		peer1 := dialer.Next(t)
		t.Cleanup(func() {
			_ = peer1.Close()
		})

		typ, body := giReadAppFrame(t, peer1, giMsgTimeout)
		if typ != giSubFrameType {
			t.Fatalf("frame type: %d != %d", typ, giSubFrameType)
		}

		var sf wire.SubFrame
		if err := proto.Unmarshal(body, &sf); err != nil {
			t.Fatal(err)
		}
		if sf.GetNum() != 1 {
			t.Fatalf("sub num: %d != %d", sf.GetNum(), 1)
		}
		if got := string(sf.GetPath()); got != "topic" {
			t.Fatalf("sub path: %q != %q", got, "topic")
		}

		msgBody := protowire.AppendTag(nil, 99, protowire.VarintType)
		msgBody = protowire.AppendVarint(msgBody, 1)
		msgBody = protowire.AppendTag(msgBody, giNumField, protowire.VarintType)
		msgBody = protowire.AppendVarint(msgBody, 1)
		msgBody = protowire.AppendTag(msgBody, giPathField, protowire.BytesType)
		msgBody = protowire.AppendBytes(msgBody, []byte("stale"))
		msgBody = protowire.AppendTag(msgBody, giDataField, protowire.BytesType)
		msgBody = protowire.AppendBytes(msgBody, []byte("old"))
		msgBody = protowire.AppendTag(msgBody, giNumField, protowire.VarintType)
		msgBody = protowire.AppendVarint(msgBody, 1)
		msgBody = protowire.AppendTag(msgBody, giPathField, protowire.BytesType)
		msgBody = protowire.AppendBytes(msgBody, []byte("topic"))
		msgBody = protowire.AppendTag(msgBody, giDataField, protowire.BytesType)
		msgBody = protowire.AppendBytes(msgBody, []byte("first"))
		msgBody = protowire.AppendTag(msgBody, giInboxField, protowire.BytesType)
		msgBody = protowire.AppendBytes(msgBody, []byte("reply"))

		giWriteFrames(t, peer1,
			giFrame(99, []byte{1, 2, 3}),
			giFrame(giMsgFrameType, msgBody),
		)
		giAssertMsg(t, giRecvMsg(t, msgC), "topic", []byte("first"), "reply")

		synctest.Wait()
		time.Sleep(1 * time.Second)
		synctest.Wait()

		typ, body = giReadFrame(t, peer1, giMsgTimeout)
		if typ != 0 || len(body) != 0 {
			t.Fatalf("keepalive: type=%d body=%x", typ, body)
		}

		giWriteFrames(t, peer1, giFrame(giMsgFrameType, nil))

		synctest.Wait()
		time.Sleep(500 * time.Millisecond)
		synctest.Wait()

		peer2 := dialer.Next(t)
		t.Cleanup(func() {
			_ = peer2.Close()
		})

		typ, body = giReadAppFrame(t, peer2, giMsgTimeout)
		if typ != giSubFrameType {
			t.Fatalf("reconnect frame type: %d != %d", typ, giSubFrameType)
		}

		if err := proto.Unmarshal(body, &sf); err != nil {
			t.Fatal(err)
		}
		if sf.GetNum() != 1 || string(sf.GetPath()) != "topic" {
			t.Fatalf("resubscribe mismatch: num=%d path=%q", sf.GetNum(), sf.GetPath())
		}

		giWriteFrames(t, peer2, giMsgFrame(1, yat.Msg{
			Path: yat.NewPath("topic"),
			Data: []byte("second"),
		}))
		giAssertMsg(t, giRecvMsg(t, msgC), "topic", []byte("second"), "")
	})
}

func TestGenIntegrationMessageDataLimit(t *testing.T) {
	t.Run("client publish boundary and recovery", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			rr := yat.NewRouter()
			srv := giMustNewServer(t, rr, yat.AllowAll())

			pub := giNewPipeClient(t, srv)
			sub := giNewPipeClient(t, srv)
			msgC, msgSub := giMustSubscribeClient(t, sub, yat.Sel{Path: yat.NewPath("data/client")})
			t.Cleanup(msgSub.Cancel)

			giWaitClientReadyPath(t, pub, "ready/client-limit-pub")
			giWaitClientReadyPath(t, sub, "ready/client-limit-sub")

			exact := make([]byte, giMaxDataLen)
			exact[0] = 'a'
			exact[len(exact)-1] = 'z'

			if err := pub.Publish(context.Background(), yat.Msg{
				Path: yat.NewPath("data/client"),
				Data: exact,
			}); err != nil {
				t.Fatal(err)
			}

			got := giRecvMsg(t, msgC)
			if got.Path.String() != "data/client" {
				t.Fatalf("path: %q != %q", got.Path.String(), "data/client")
			}
			if !bytes.Equal(got.Data, exact) {
				t.Fatalf("data length: %d != %d", len(got.Data), len(exact))
			}
			if !got.Inbox.IsZero() {
				t.Fatalf("unexpected inbox: %q", got.Inbox)
			}

			if err := pub.Publish(context.Background(), yat.Msg{
				Path: yat.NewPath("data/client"),
				Data: make([]byte, giMaxDataLen+1),
			}); err == nil || err.Error() != giErrLongData {
				t.Fatalf("publish long data: %v", err)
			}

			if err := pub.Publish(context.Background(), yat.Msg{
				Path: yat.NewPath("data/client"),
				Data: []byte("after-long-data"),
			}); err != nil {
				t.Fatal(err)
			}
			giAssertMsg(t, giRecvMsg(t, msgC), "data/client", []byte("after-long-data"), "")
		})
	})

	t.Run("router publish boundary", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			rr := yat.NewRouter()
			srv := giMustNewServer(t, rr, yat.AllowAll())

			sub := giNewPipeClient(t, srv)
			msgC, msgSub := giMustSubscribeClient(t, sub, yat.Sel{Path: yat.NewPath("data/router")})
			t.Cleanup(msgSub.Cancel)

			giWaitClientReadyPath(t, sub, "ready/router-limit-sub")

			exact := make([]byte, giMaxDataLen)
			exact[0] = 'r'
			exact[len(exact)-1] = 'R'

			if err := rr.Publish(context.Background(), yat.Msg{
				Path: yat.NewPath("data/router"),
				Data: exact,
			}); err != nil {
				t.Fatal(err)
			}

			got := giRecvMsg(t, msgC)
			if got.Path.String() != "data/router" {
				t.Fatalf("path: %q != %q", got.Path.String(), "data/router")
			}
			if !bytes.Equal(got.Data, exact) {
				t.Fatalf("data length: %d != %d", len(got.Data), len(exact))
			}

			if err := rr.Publish(context.Background(), yat.Msg{
				Path: yat.NewPath("data/router"),
				Data: make([]byte, giMaxDataLen+1),
			}); err == nil || err.Error() != giErrLongData {
				t.Fatalf("publish long data: %v", err)
			}
			giExpectNoMsg(t, msgC)
		})
	})

	t.Run("server pub frame oversize closes connection", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			rr := yat.NewRouter()
			srv := giMustNewServer(t, rr, yat.AllowAll())
			peer, done := giServeRawPeer(t, srv)
			t.Cleanup(func() {
				_ = peer.Close()
				<-done
			})

			msgC, sub := giMustSubscribeRouter(t, rr, yat.Sel{Path: yat.NewPath("data/server")})
			t.Cleanup(sub.Cancel)

			exact := make([]byte, giMaxDataLen)
			exact[0] = 's'
			exact[len(exact)-1] = 'S'

			giWriteFrames(t, peer, giPubFrame(yat.Msg{
				Path: yat.NewPath("data/server"),
				Data: exact,
			}))

			got := giRecvMsg(t, msgC)
			if got.Path.String() != "data/server" {
				t.Fatalf("path: %q != %q", got.Path.String(), "data/server")
			}
			if !bytes.Equal(got.Data, exact) {
				t.Fatalf("data length: %d != %d", len(got.Data), len(exact))
			}

			giWriteFrames(t, peer, giPubFrame(yat.Msg{
				Path: yat.NewPath("data/server"),
				Data: make([]byte, giMaxDataLen+1),
			}))

			giExpectNoMsg(t, msgC)
			giExpectConnClose(t, peer)
		})
	})

	t.Run("client msg frame oversize closes connection and reconnects", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			dialer := giNewPeerDialer()
			c, err := yat.NewClient(dialer.Dial, yat.ClientConfig{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				dialer.Close()
				_ = c.Close()
			})

			msgC, sub := giMustSubscribeClient(t, c, yat.Sel{Path: yat.NewPath("data/client-inbound")})
			t.Cleanup(sub.Cancel)

			peer1 := dialer.Next(t)
			t.Cleanup(func() {
				_ = peer1.Close()
			})

			typ, body := giReadAppFrame(t, peer1, giMsgTimeout)
			if typ != giSubFrameType {
				t.Fatalf("frame type: %d != %d", typ, giSubFrameType)
			}

			var sf wire.SubFrame
			if err := proto.Unmarshal(body, &sf); err != nil {
				t.Fatal(err)
			}
			if sf.GetNum() != 1 || string(sf.GetPath()) != "data/client-inbound" {
				t.Fatalf("subscribe mismatch: num=%d path=%q", sf.GetNum(), sf.GetPath())
			}

			exact := make([]byte, giMaxDataLen)
			exact[0] = 'c'
			exact[len(exact)-1] = 'C'

			giWriteFrames(t, peer1, giMsgFrame(1, yat.Msg{
				Path: yat.NewPath("data/client-inbound"),
				Data: exact,
			}))

			got := giRecvMsg(t, msgC)
			if got.Path.String() != "data/client-inbound" {
				t.Fatalf("path: %q != %q", got.Path.String(), "data/client-inbound")
			}
			if !bytes.Equal(got.Data, exact) {
				t.Fatalf("data length: %d != %d", len(got.Data), len(exact))
			}

			giWriteFrames(t, peer1, giMsgFrame(1, yat.Msg{
				Path: yat.NewPath("data/client-inbound"),
				Data: make([]byte, giMaxDataLen+1),
			}))

			giExpectNoMsg(t, msgC)
			giExpectConnClose(t, peer1)

			synctest.Wait()
			time.Sleep(500 * time.Millisecond)
			synctest.Wait()

			peer2 := dialer.Next(t)
			t.Cleanup(func() {
				_ = peer2.Close()
			})

			typ, body = giReadAppFrame(t, peer2, giMsgTimeout)
			if typ != giSubFrameType {
				t.Fatalf("reconnect frame type: %d != %d", typ, giSubFrameType)
			}
			if err := proto.Unmarshal(body, &sf); err != nil {
				t.Fatal(err)
			}
			if sf.GetNum() != 1 || string(sf.GetPath()) != "data/client-inbound" {
				t.Fatalf("resubscribe mismatch: num=%d path=%q", sf.GetNum(), sf.GetPath())
			}

			giWriteFrames(t, peer2, giMsgFrame(1, yat.Msg{
				Path: yat.NewPath("data/client-inbound"),
				Data: []byte("after-reconnect"),
			}))
			giAssertMsg(t, giRecvMsg(t, msgC), "data/client-inbound", []byte("after-reconnect"), "")
		})
	})

}

func TestGenIntegrationServerProtocolRawPeer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rr := yat.NewRouter()
		srv := giMustNewServer(t, rr, yat.AllowAll())
		peer, done := giServeRawPeer(t, srv)
		t.Cleanup(func() {
			_ = peer.Close()
			<-done
		})

		localC, localSub := giMustSubscribeRouter(t, rr, yat.Sel{Path: yat.NewPath("inbound")})
		t.Cleanup(localSub.Cancel)

		giWriteFrames(t, peer,
			giFrame(99, []byte{1, 2, 3}),
			giSubFrame(t, 7, yat.Sel{Path: yat.NewPath("topic"), Limit: 1}),
		)
		synctest.Wait()

		if err := rr.Publish(context.Background(), yat.Msg{
			Path: yat.NewPath("topic"),
			Data: []byte("first"),
		}); err != nil {
			t.Fatal(err)
		}

		typ, body := giReadAppFrame(t, peer, giMsgTimeout)
		if typ != giMsgFrameType {
			t.Fatalf("frame type: %d != %d", typ, giMsgFrameType)
		}
		num, msg := giDecodeSharedFields(t, body)
		if num != 7 {
			t.Fatalf("msg num: %d != %d", num, 7)
		}
		giAssertMsg(t, msg, "topic", []byte("first"), "")

		if err := rr.Publish(context.Background(), yat.Msg{
			Path: yat.NewPath("topic"),
			Data: []byte("second"),
		}); err != nil {
			t.Fatal(err)
		}
		giExpectNoAppFrame(t, peer, giNoMsgTimeout)

		giWriteFrames(t, peer, giSubFrame(t, 8, yat.Sel{Path: yat.NewPath("updates")}))
		synctest.Wait()
		if err := rr.Publish(context.Background(), yat.Msg{
			Path: yat.NewPath("updates"),
			Data: []byte("u1"),
		}); err != nil {
			t.Fatal(err)
		}

		typ, body = giReadAppFrame(t, peer, giMsgTimeout)
		if typ != giMsgFrameType {
			t.Fatalf("frame type: %d != %d", typ, giMsgFrameType)
		}
		num, msg = giDecodeSharedFields(t, body)
		if num != 8 {
			t.Fatalf("msg num: %d != %d", num, 8)
		}
		giAssertMsg(t, msg, "updates", []byte("u1"), "")

		giWriteFrames(t, peer, giUnsubFrame(t, 8))
		synctest.Wait()
		if err := rr.Publish(context.Background(), yat.Msg{
			Path: yat.NewPath("updates"),
			Data: []byte("u2"),
		}); err != nil {
			t.Fatal(err)
		}
		giExpectNoAppFrame(t, peer, giNoMsgTimeout)

		pubBody := protowire.AppendTag(nil, 99, protowire.VarintType)
		pubBody = protowire.AppendVarint(pubBody, 1)
		pubBody = protowire.AppendTag(pubBody, giPathField, protowire.BytesType)
		pubBody = protowire.AppendBytes(pubBody, []byte("stale"))
		pubBody = protowire.AppendTag(pubBody, giDataField, protowire.BytesType)
		pubBody = protowire.AppendBytes(pubBody, []byte("old"))
		pubBody = protowire.AppendTag(pubBody, giPathField, protowire.BytesType)
		pubBody = protowire.AppendBytes(pubBody, []byte("inbound"))
		pubBody = protowire.AppendTag(pubBody, giDataField, protowire.BytesType)
		pubBody = protowire.AppendBytes(pubBody, []byte("from-peer"))
		pubBody = protowire.AppendTag(pubBody, giInboxField, protowire.BytesType)
		pubBody = protowire.AppendBytes(pubBody, []byte("reply"))

		giWriteFrames(t, peer, giFrame(giPubFrameType, pubBody))
		synctest.Wait()
		giAssertMsg(t, giRecvMsg(t, localC), "inbound", []byte("from-peer"), "reply")

		synctest.Wait()
		time.Sleep(1 * time.Second)
		synctest.Wait()

		typ, body = giReadFrame(t, peer, giMsgTimeout)
		if typ != 0 || len(body) != 0 {
			t.Fatalf("keepalive: type=%d body=%x", typ, body)
		}
	})
}

func TestGenIntegrationServerProtocolRules(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rr := yat.NewRouter()
		rules, err := yat.NewRuleSet([]yat.Rule{{
			Grants: []yat.Grant{
				{
					Path:    yat.NewPath("allowed/pub"),
					Actions: []yat.Action{yat.ActionPub},
				},
				{
					Path:    yat.NewPath("allowed/sub"),
					Actions: []yat.Action{yat.ActionSub},
				},
			},
		}})
		if err != nil {
			t.Fatal(err)
		}

		srv := giMustNewServer(t, rr, rules)
		peer, done := giServeRawPeer(t, srv)
		t.Cleanup(func() {
			_ = peer.Close()
			<-done
		})

		pubC, pubSub := giMustSubscribeRouter(t, rr, yat.Sel{Path: yat.NewPath("allowed/pub")})
		t.Cleanup(pubSub.Cancel)

		giWriteFrames(t, peer, giSubFrame(t, 1, yat.Sel{Path: yat.NewPath("denied/sub")}))
		synctest.Wait()
		if err := rr.Publish(context.Background(), yat.Msg{
			Path: yat.NewPath("denied/sub"),
			Data: []byte("blocked"),
		}); err != nil {
			t.Fatal(err)
		}
		giExpectNoAppFrame(t, peer, giNoMsgTimeout)

		giWriteFrames(t, peer, giPubFrame(yat.Msg{
			Path: yat.NewPath("denied/pub"),
			Data: []byte("blocked"),
		}))
		synctest.Wait()
		giExpectNoMsg(t, pubC)

		giWriteFrames(t, peer, giPubFrame(yat.Msg{
			Path:  yat.NewPath("allowed/pub"),
			Data:  []byte("blocked-inbox"),
			Inbox: yat.NewPath("reply/blocked"),
		}))
		synctest.Wait()
		giExpectNoMsg(t, pubC)

		giWriteFrames(t, peer, giSubFrame(t, 2, yat.Sel{Path: yat.NewPath("allowed/sub")}))
		synctest.Wait()
		if err := rr.Publish(context.Background(), yat.Msg{
			Path: yat.NewPath("allowed/sub"),
			Data: []byte("sub-ok"),
		}); err != nil {
			t.Fatal(err)
		}

		typ, body := giReadAppFrame(t, peer, giMsgTimeout)
		if typ != giMsgFrameType {
			t.Fatalf("frame type: %d != %d", typ, giMsgFrameType)
		}
		num, msg := giDecodeSharedFields(t, body)
		if num != 2 {
			t.Fatalf("msg num: %d != %d", num, 2)
		}
		giAssertMsg(t, msg, "allowed/sub", []byte("sub-ok"), "")

		giWriteFrames(t, peer, giPubFrame(yat.Msg{
			Path: yat.NewPath("allowed/pub"),
			Data: []byte("pub-ok"),
		}))
		synctest.Wait()
		giAssertMsg(t, giRecvMsg(t, pubC), "allowed/pub", []byte("pub-ok"), "")
	})
}

func TestGenIntegrationRouterAndClients(t *testing.T) {
	t.Run("same client loopback and cancel", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			rr := yat.NewRouter()
			srv := giMustNewServer(t, rr, yat.AllowAll())
			c := giNewPipeClient(t, srv)

			msgC, sub := giMustSubscribeClient(t, c, yat.Sel{Path: yat.NewPath("path")})
			t.Cleanup(sub.Cancel)
			giWaitClientReadyPath(t, c, "ready/same")

			if err := c.Publish(context.Background(), yat.Msg{
				Path:  yat.NewPath("path"),
				Data:  []byte("first"),
				Inbox: yat.NewPath("inbox"),
			}); err != nil {
				t.Fatal(err)
			}
			giAssertMsg(t, giRecvMsg(t, msgC), "path", []byte("first"), "inbox")

			if err := c.Publish(context.Background(), yat.Msg{
				Path: yat.NewPath("other"),
				Data: []byte("stale"),
			}); err != nil {
				t.Fatal(err)
			}
			giExpectNoMsg(t, msgC)

			sub.Cancel()
			select {
			case <-sub.Done():
			default:
				t.Fatal("sub done was not closed")
			}

			if err := c.Publish(context.Background(), yat.Msg{
				Path: yat.NewPath("path"),
				Data: []byte("gone"),
			}); err != nil {
				t.Fatal(err)
			}
			giExpectNoMsg(t, msgC)
		})
	})

	t.Run("fanout and router publishing", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			rr := yat.NewRouter()
			srv := giMustNewServer(t, rr, yat.AllowAll())

			sub1 := giNewPipeClient(t, srv)
			sub2 := giNewPipeClient(t, srv)
			nomatch := giNewPipeClient(t, srv)
			pub := giNewPipeClient(t, srv)

			sub1C, sub1Sub := giMustSubscribeClient(t, sub1, yat.Sel{Path: yat.NewPath("a")})
			sub2C, sub2Sub := giMustSubscribeClient(t, sub2, yat.Sel{Path: yat.NewPath("a")})
			negC, negSub := giMustSubscribeClient(t, nomatch, yat.Sel{Path: yat.NewPath("b")})
			t.Cleanup(sub1Sub.Cancel)
			t.Cleanup(sub2Sub.Cancel)
			t.Cleanup(negSub.Cancel)

			giWaitClientReadyPath(t, sub1, "ready/sub1")
			giWaitClientReadyPath(t, sub2, "ready/sub2")
			giWaitClientReadyPath(t, nomatch, "ready/neg")
			giWaitClientReadyPath(t, pub, "ready/pub")

			if err := pub.Publish(context.Background(), yat.Msg{
				Path: yat.NewPath("a"),
				Data: []byte("fanout-1"),
			}); err != nil {
				t.Fatal(err)
			}
			if err := pub.Publish(context.Background(), yat.Msg{
				Path: yat.NewPath("a"),
				Data: []byte("fanout-2"),
			}); err != nil {
				t.Fatal(err)
			}

			seen1 := map[string]bool{
				string(giRecvMsg(t, sub1C).Data): true,
				string(giRecvMsg(t, sub1C).Data): true,
			}
			if !seen1["fanout-1"] || !seen1["fanout-2"] {
				t.Fatalf("sub1 messages: %#v", seen1)
			}

			seen2 := map[string]bool{
				string(giRecvMsg(t, sub2C).Data): true,
				string(giRecvMsg(t, sub2C).Data): true,
			}
			if !seen2["fanout-1"] || !seen2["fanout-2"] {
				t.Fatalf("sub2 messages: %#v", seen2)
			}

			giExpectNoMsg(t, negC)

			routerC, routerSub := giMustSubscribeRouter(t, rr, yat.Sel{Path: yat.NewPath("b")})
			t.Cleanup(routerSub.Cancel)

			if err := pub.Publish(context.Background(), yat.Msg{
				Path:  yat.NewPath("b"),
				Data:  []byte("from-client"),
				Inbox: yat.NewPath("inbox"),
			}); err != nil {
				t.Fatal(err)
			}
			giAssertMsg(t, giRecvMsg(t, routerC), "b", []byte("from-client"), "inbox")

			if err := rr.Publish(context.Background(), yat.Msg{
				Path:  yat.NewPath("a"),
				Data:  []byte("from-router"),
				Inbox: yat.NewPath("router/inbox"),
			}); err != nil {
				t.Fatal(err)
			}
			giAssertMsg(t, giRecvMsg(t, sub1C), "a", []byte("from-router"), "router/inbox")
			giAssertMsg(t, giRecvMsg(t, sub2C), "a", []byte("from-router"), "router/inbox")
		})
	})

	t.Run("grouped routing and limits", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			rr := yat.NewRouter()
			srv := giMustNewServer(t, rr, yat.AllowAll())

			g1a := giNewPipeClient(t, srv)
			g1b := giNewPipeClient(t, srv)
			g2a := giNewPipeClient(t, srv)
			g2b := giNewPipeClient(t, srv)
			lit := giNewPipeClient(t, srv)
			w1 := giNewPipeClient(t, srv)
			w2 := giNewPipeClient(t, srv)
			limited := giNewPipeClient(t, srv)
			pub := giNewPipeClient(t, srv)

			g1aC, g1aSub := giMustSubscribeClient(t, g1a, yat.Sel{
				Path:  yat.NewPath("topic/a/b"),
				Group: yat.NewGroup("g1"),
			})
			g1bC, g1bSub := giMustSubscribeClient(t, g1b, yat.Sel{
				Path:  yat.NewPath("topic/a/*"),
				Group: yat.NewGroup("g1"),
			})
			g2aC, g2aSub := giMustSubscribeClient(t, g2a, yat.Sel{
				Path:  yat.NewPath("topic/a/b"),
				Group: yat.NewGroup("g2"),
			})
			g2bC, g2bSub := giMustSubscribeClient(t, g2b, yat.Sel{
				Path:  yat.NewPath("topic/*/b"),
				Group: yat.NewGroup("g2"),
			})
			litC, litSub := giMustSubscribeClient(t, lit, yat.Sel{Path: yat.NewPath("topic/a/b")})
			w1C, w1Sub := giMustSubscribeClient(t, w1, yat.Sel{Path: yat.NewPath("topic/a/*")})
			w2C, w2Sub := giMustSubscribeClient(t, w2, yat.Sel{Path: yat.NewPath("topic/*/b")})
			limitedC, limitedSub := giMustSubscribeClient(t, limited, yat.Sel{
				Path:  yat.NewPath("topic/a/b"),
				Limit: 1,
			})

			t.Cleanup(g1aSub.Cancel)
			t.Cleanup(g1bSub.Cancel)
			t.Cleanup(g2aSub.Cancel)
			t.Cleanup(g2bSub.Cancel)
			t.Cleanup(litSub.Cancel)
			t.Cleanup(w1Sub.Cancel)
			t.Cleanup(w2Sub.Cancel)
			t.Cleanup(limitedSub.Cancel)

			giWaitClientReadyPath(t, g1a, "ready/g1a")
			giWaitClientReadyPath(t, g1b, "ready/g1b")
			giWaitClientReadyPath(t, g2a, "ready/g2a")
			giWaitClientReadyPath(t, g2b, "ready/g2b")
			giWaitClientReadyPath(t, lit, "ready/lit")
			giWaitClientReadyPath(t, w1, "ready/w1")
			giWaitClientReadyPath(t, w2, "ready/w2")
			giWaitClientReadyPath(t, limited, "ready/limited")
			giWaitClientReadyPath(t, pub, "ready/pub")

			const npub = 96
			for i := range npub {
				if err := pub.Publish(context.Background(), yat.Msg{
					Path: yat.NewPath("topic/a/b"),
					Data: []byte{byte(i)},
				}); err != nil {
					t.Fatal(err)
				}
			}

			synctest.Wait()

			if got := giDrainMsgCount(g1aC) + giDrainMsgCount(g1bC); got != npub {
				t.Fatalf("g1 deliveries: %d != %d", got, npub)
			}
			if got := giDrainMsgCount(g2aC) + giDrainMsgCount(g2bC); got != npub {
				t.Fatalf("g2 deliveries: %d != %d", got, npub)
			}
			if got := giDrainMsgCount(litC); got != npub {
				t.Fatalf("literal deliveries: %d != %d", got, npub)
			}
			if got := giDrainMsgCount(w1C); got != npub {
				t.Fatalf("wildcard deliveries: %d != %d", got, npub)
			}
			if got := giDrainMsgCount(w2C); got != npub {
				t.Fatalf("wildcard deliveries: %d != %d", got, npub)
			}
			if got := giDrainMsgCount(limitedC); got != 1 {
				t.Fatalf("limited deliveries: %d != 1", got)
			}
			select {
			case <-limitedSub.Done():
			default:
				t.Fatal("limited subscription did not complete")
			}
		})
	})
}

func TestGenIntegrationSharedRouterAcrossServers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rr := yat.NewRouter()
		srv1 := giMustNewServer(t, rr, yat.AllowAll())
		srv2 := giMustNewServer(t, rr, yat.AllowAll())

		sub1 := giNewPipeClient(t, srv1)
		sub2 := giNewPipeClient(t, srv2)
		pub1 := giNewPipeClient(t, srv1)
		pub2 := giNewPipeClient(t, srv2)

		sub1C, sub1Sub := giMustSubscribeClient(t, sub1, yat.Sel{Path: yat.NewPath("path")})
		sub2C, sub2Sub := giMustSubscribeClient(t, sub2, yat.Sel{Path: yat.NewPath("path")})
		t.Cleanup(sub1Sub.Cancel)
		t.Cleanup(sub2Sub.Cancel)

		giWaitClientReadyPath(t, sub1, "ready/sub1")
		giWaitClientReadyPath(t, sub2, "ready/sub2")
		giWaitClientReadyPath(t, pub1, "ready/pub1")
		giWaitClientReadyPath(t, pub2, "ready/pub2")

		if err := pub1.Publish(context.Background(), yat.Msg{
			Path:  yat.NewPath("path"),
			Data:  []byte("from-srv-1"),
			Inbox: yat.NewPath("inbox/a"),
		}); err != nil {
			t.Fatal(err)
		}
		giAssertMsg(t, giRecvMsg(t, sub1C), "path", []byte("from-srv-1"), "inbox/a")
		giAssertMsg(t, giRecvMsg(t, sub2C), "path", []byte("from-srv-1"), "inbox/a")

		if err := pub2.Publish(context.Background(), yat.Msg{
			Path:  yat.NewPath("path"),
			Data:  []byte("from-srv-2"),
			Inbox: yat.NewPath("inbox/b"),
		}); err != nil {
			t.Fatal(err)
		}
		giAssertMsg(t, giRecvMsg(t, sub1C), "path", []byte("from-srv-2"), "inbox/b")
		giAssertMsg(t, giRecvMsg(t, sub2C), "path", []byte("from-srv-2"), "inbox/b")

		if err := rr.Publish(context.Background(), yat.Msg{
			Path:  yat.NewPath("path"),
			Data:  []byte("from-router"),
			Inbox: yat.NewPath("inbox"),
		}); err != nil {
			t.Fatal(err)
		}
		giAssertMsg(t, giRecvMsg(t, sub1C), "path", []byte("from-router"), "inbox")
		giAssertMsg(t, giRecvMsg(t, sub2C), "path", []byte("from-router"), "inbox")
	})
}

func TestGenIntegrationTLSWithoutClientCert(t *testing.T) {
	ca, caKey, err := pkigen.NewRoot(pkigen.CN("tls-root"))
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca)

	serverCert := giLeafCertificate(t, ca, caKey,
		pkigen.CN("server"),
		pkigen.DNS("localhost"),
	)

	rr := yat.NewRouter()
	srv := giMustNewServer(t, rr, yat.AllowAll())

	// No client auth here: accepted TLS connections have an empty VerifiedChains.
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
	})
	if err != nil {
		t.Fatal(err)
	}

	serveC := make(chan error, 1)
	go func() {
		serveC <- srv.Serve(l)
	}()

	t.Cleanup(func() {
		_ = l.Close()
		err := <-serveC
		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("serve: %v", err)
		}
	})

	dialer := tls.Dialer{
		Config: &tls.Config{
			MinVersion: tls.VersionTLS13,
			ServerName: "localhost",
			RootCAs:    roots,
		},
	}

	client, err := yat.NewClient(func(ctx context.Context) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp", l.Addr().String())
	}, yat.ClientConfig{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = client.Close()
	})

	giWaitClientReadyPath(t, client, "ready/no-client-cert")

	routerC, routerSub := giMustSubscribeRouter(t, rr, yat.Sel{Path: yat.NewPath("from/client")})
	t.Cleanup(routerSub.Cancel)

	if err := client.Publish(context.Background(), yat.Msg{
		Path: yat.NewPath("from/client"),
		Data: []byte("payload"),
	}); err != nil {
		t.Fatal(err)
	}
	giAssertMsg(t, giRecvMsg(t, routerC), "from/client", []byte("payload"), "")

	clientC, clientSub := giMustSubscribeClient(t, client, yat.Sel{Path: yat.NewPath("from/router")})
	t.Cleanup(clientSub.Cancel)
	giWaitClientReadyPath(t, client, "ready/from-router-sub")

	if err := rr.Publish(context.Background(), yat.Msg{
		Path: yat.NewPath("from/router"),
		Data: []byte("payload"),
	}); err != nil {
		t.Fatal(err)
	}
	giAssertMsg(t, giRecvMsg(t, clientC), "from/router", []byte("payload"), "")
}

func TestGenIntegrationSPIFFERulesOverTLS(t *testing.T) {
	ca, caKey, err := pkigen.NewRoot(pkigen.CN("auth-root"))
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca)

	serverCert := giLeafCertificate(t, ca, caKey,
		pkigen.CN("server"),
		pkigen.DNS("localhost"),
	)
	allowedCert := giLeafCertificate(t, ca, caKey,
		pkigen.CN("allowed"),
		pkigen.URI("spiffe://trust-domain/a/b"),
	)

	rules, err := yat.NewRuleSet([]yat.Rule{
		{
			Grants: []yat.Grant{{
				Path:    yat.NewPath("a/**"),
				Actions: []yat.Action{yat.ActionPub, yat.ActionSub},
			}},
		},
		{
			SPIFFE: &yat.SPIFFECond{
				Domain: "trust-domain",
				Path:   yat.NewPath("a/b"),
			},
			Grants: []yat.Grant{{
				Path:    yat.NewPath("b/**"),
				Actions: []yat.Action{yat.ActionPub, yat.ActionSub},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	addr := giStartTLSServer(t, rules, serverCert, roots)
	watcher := giNewTLSClient(t, addr, roots, allowedCert)
	publisher := giNewTLSClient(t, addr, roots, allowedCert)

	giWaitClientReadyPath(t, watcher, "a/ready/watch")
	giWaitClientReadyPath(t, publisher, "a/ready/publisher")

	watchC, watchSub := giMustSubscribeClient(t, watcher, yat.Sel{Path: yat.NewPath("b/a")})
	t.Cleanup(watchSub.Cancel)
	giWaitClientReadyPath(t, watcher, "a/ready/watch-sub")

	cases := []struct {
		name    string
		opts    []pkigen.CertOpt
		wantSub bool
		wantPub bool
	}{
		{
			name:    "matching spiffe id",
			opts:    []pkigen.CertOpt{pkigen.URI("spiffe://trust-domain/a/b")},
			wantSub: true,
			wantPub: true,
		},
		{
			name: "domain mismatch",
			opts: []pkigen.CertOpt{pkigen.URI("spiffe://other-domain/a/b")},
		},
		{
			name: "path mismatch",
			opts: []pkigen.CertOpt{pkigen.URI("spiffe://trust-domain/a/c")},
		},
		{
			name: "no uri san",
		},
		{
			name: "multiple uri sans",
			opts: []pkigen.CertOpt{
				pkigen.URI("spiffe://trust-domain/a/b"),
				pkigen.URI("spiffe://trust-domain/extra"),
			},
		},
		{
			name: "wrong scheme",
			opts: []pkigen.CertOpt{pkigen.URI("https://trust-domain/a/b")},
		},
		{
			name: "query rejected",
			opts: []pkigen.CertOpt{pkigen.URI("spiffe://trust-domain/a/b?x=1")},
		},
		{
			name: "force query rejected",
			opts: []pkigen.CertOpt{pkigen.URI("spiffe://trust-domain/a/b?")},
		},
		{
			name: "userinfo rejected",
			opts: []pkigen.CertOpt{pkigen.URI("spiffe://user@trust-domain/a/b")},
		},
		{
			name: "invalid trust domain rejected",
			opts: []pkigen.CertOpt{pkigen.URI("spiffe://trust-domain:443/a/b")},
		},
		{
			name: "wild path rejected",
			opts: []pkigen.CertOpt{pkigen.URI("spiffe://trust-domain/*")},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			opts := append([]pkigen.CertOpt{pkigen.CN(tc.name)}, tc.opts...)
			caseCert := giLeafCertificate(t, ca, caKey, opts...)
			client := giNewTLSClient(t, addr, roots, caseCert)

			giWaitClientReadyPath(t, client, "a/ready/"+tc.name)

			caseC, caseSub := giMustSubscribeClient(t, client, yat.Sel{Path: yat.NewPath("b/a")})
			t.Cleanup(caseSub.Cancel)
			giWaitClientReadyPath(t, client, "a/subready/"+tc.name)

			if err := publisher.Publish(context.Background(), yat.Msg{
				Path: yat.NewPath("b/a"),
				Data: []byte("from-allowed"),
			}); err != nil {
				t.Fatal(err)
			}

			giAssertMsg(t, giRecvMsg(t, watchC), "b/a", []byte("from-allowed"), "")
			if tc.wantSub {
				giAssertMsg(t, giRecvMsg(t, caseC), "b/a", []byte("from-allowed"), "")
			} else {
				giExpectNoMsg(t, caseC)
			}

			if err := client.Publish(context.Background(), yat.Msg{
				Path: yat.NewPath("b/a"),
				Data: []byte("from-case"),
			}); err != nil {
				t.Fatal(err)
			}

			if tc.wantPub {
				giAssertMsg(t, giRecvMsg(t, watchC), "b/a", []byte("from-case"), "")
			} else {
				giExpectNoMsg(t, watchC)
			}
		})
	}

	t.Run("domain only matches pathless spiffe id", func(t *testing.T) {
		pathlessCert := giLeafCertificate(t, ca, caKey,
			pkigen.CN("pathless"),
			pkigen.URI("spiffe://trust-domain"),
		)

		domainRules, err := yat.NewRuleSet([]yat.Rule{
			{
				Grants: []yat.Grant{{
					Path:    yat.NewPath("a/**"),
					Actions: []yat.Action{yat.ActionPub, yat.ActionSub},
				}},
			},
			{
				SPIFFE: &yat.SPIFFECond{Domain: "trust-domain"},
				Grants: []yat.Grant{{
					Path:    yat.NewPath("b/**"),
					Actions: []yat.Action{yat.ActionPub, yat.ActionSub},
				}},
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		domainAddr := giStartTLSServer(t, domainRules, serverCert, roots)
		watcher := giNewTLSClient(t, domainAddr, roots, pathlessCert)
		client := giNewTLSClient(t, domainAddr, roots, pathlessCert)

		giWaitClientReadyPath(t, watcher, "a/ready/domain-watch")
		giWaitClientReadyPath(t, client, "a/ready/domain-client")

		watchC, watchSub := giMustSubscribeClient(t, watcher, yat.Sel{Path: yat.NewPath("b/a")})
		caseC, caseSub := giMustSubscribeClient(t, client, yat.Sel{Path: yat.NewPath("b/a")})
		t.Cleanup(watchSub.Cancel)
		t.Cleanup(caseSub.Cancel)

		giWaitClientReadyPath(t, watcher, "a/ready/domain-watch-sub")
		giWaitClientReadyPath(t, client, "a/ready/domain-client-sub")

		if err := client.Publish(context.Background(), yat.Msg{
			Path: yat.NewPath("b/a"),
			Data: []byte("pathless"),
		}); err != nil {
			t.Fatal(err)
		}

		giAssertMsg(t, giRecvMsg(t, watchC), "b/a", []byte("pathless"), "")
		giAssertMsg(t, giRecvMsg(t, caseC), "b/a", []byte("pathless"), "")
	})
}

func giMustNewServer(t *testing.T, rr *yat.Router, rules *yat.RuleSet) *yat.Server {
	t.Helper()

	srv, err := yat.NewServer(rr, yat.ServerConfig{Rules: rules})
	if err != nil {
		t.Fatal(err)
	}

	return srv
}

func giNewPipeClient(t *testing.T, srv *yat.Server) *yat.Client {
	t.Helper()

	var wg sync.WaitGroup

	c, err := yat.NewClient(func(context.Context) (net.Conn, error) {
		serverConn, clientConn := net.Pipe()
		wg.Add(1)
		go func() {
			defer wg.Done()
			srv.ServeConn(context.Background(), serverConn)
		}()
		return clientConn, nil
	}, yat.ClientConfig{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = c.Close()
		wg.Wait()
	})

	return c
}

func giServeRawPeer(t *testing.T, srv *yat.Server) (net.Conn, <-chan struct{}) {
	t.Helper()

	serverConn, peer := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.ServeConn(context.Background(), serverConn)
	}()

	return peer, done
}

type giPeerDialer struct {
	mu    sync.Mutex
	peers []net.Conn
	peerC chan net.Conn
}

func giNewPeerDialer() *giPeerDialer {
	return &giPeerDialer{
		peerC: make(chan net.Conn, 8),
	}
}

func (d *giPeerDialer) Dial(context.Context) (net.Conn, error) {
	peer, client := net.Pipe()

	d.mu.Lock()
	d.peers = append(d.peers, peer)
	d.mu.Unlock()

	d.peerC <- peer
	return client, nil
}

func (d *giPeerDialer) Next(t *testing.T) net.Conn {
	t.Helper()

	select {
	case peer := <-d.peerC:
		return peer
	case <-time.After(giMsgTimeout):
		t.Fatal("peer timeout")
		return nil
	}
}

func (d *giPeerDialer) Close() {
	d.mu.Lock()
	peers := append([]net.Conn(nil), d.peers...)
	d.peers = nil
	d.mu.Unlock()

	for _, peer := range peers {
		_ = peer.Close()
	}
}

func giLeafCertificate(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, opts ...pkigen.CertOpt) tls.Certificate {
	t.Helper()

	leaf, key, err := pkigen.NewLeaf(ca, caKey, opts...)
	if err != nil {
		t.Fatal(err)
	}

	return tls.Certificate{
		Certificate: [][]byte{leaf.Raw},
		PrivateKey:  key,
		Leaf:        leaf,
	}
}

func giStartTLSServer(t *testing.T, rules *yat.RuleSet, cert tls.Certificate, roots *x509.CertPool) string {
	t.Helper()

	srv := giMustNewServer(t, yat.NewRouter(), rules)
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    roots,
	})
	if err != nil {
		t.Fatal(err)
	}

	serveC := make(chan error, 1)
	go func() {
		serveC <- srv.Serve(l)
	}()

	t.Cleanup(func() {
		_ = l.Close()
		err := <-serveC
		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("serve: %v", err)
		}
	})

	return l.Addr().String()
}

func giNewTLSClient(t *testing.T, addr string, roots *x509.CertPool, cert tls.Certificate) *yat.Client {
	t.Helper()

	dialer := tls.Dialer{
		Config: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			ServerName:   "localhost",
			RootCAs:      roots,
			Certificates: []tls.Certificate{cert},
		},
	}

	c, err := yat.NewClient(func(ctx context.Context) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp", addr)
	}, yat.ClientConfig{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = c.Close()
	})

	return c
}

func giMustSubscribeClient(t *testing.T, c *yat.Client, sel yat.Sel) (<-chan yat.Msg, yat.Sub) {
	t.Helper()

	msgC := make(chan yat.Msg, 256)
	sub, err := c.Subscribe(sel, func(_ context.Context, m yat.Msg) {
		msgC <- giCloneMsg(m)
	})
	if err != nil {
		t.Fatal(err)
	}

	return msgC, sub
}

func giMustSubscribeRouter(t *testing.T, rr *yat.Router, sel yat.Sel) (<-chan yat.Msg, yat.Sub) {
	t.Helper()

	msgC := make(chan yat.Msg, 256)
	sub, err := rr.Subscribe(sel, func(_ context.Context, m yat.Msg) {
		msgC <- giCloneMsg(m)
	})
	if err != nil {
		t.Fatal(err)
	}

	return msgC, sub
}

func giWaitClientReadyPath(t *testing.T, c *yat.Client, path string) {
	t.Helper()

	msgC, sub := giMustSubscribeClient(t, c, yat.Sel{Path: yat.NewPath(path)})
	defer sub.Cancel()

	if err := c.Publish(context.Background(), yat.Msg{
		Path: yat.NewPath(path),
		Data: []byte("ready"),
	}); err != nil {
		t.Fatal(err)
	}

	giAssertMsg(t, giRecvMsg(t, msgC), path, []byte("ready"), "")
}

func giRecvMsg(t *testing.T, msgC <-chan yat.Msg) yat.Msg {
	t.Helper()

	select {
	case msg := <-msgC:
		return msg
	case <-time.After(giMsgTimeout):
		t.Fatal("message timeout")
		return yat.Msg{}
	}
}

func giExpectNoMsg(t *testing.T, msgC <-chan yat.Msg) {
	t.Helper()

	select {
	case msg := <-msgC:
		t.Fatalf("unexpected message: path=%q data=%q inbox=%q", msg.Path, msg.Data, msg.Inbox)
	case <-time.After(giNoMsgTimeout):
	}
}

func giDrainMsgCount(msgC <-chan yat.Msg) (n int) {
	for {
		select {
		case <-msgC:
			n++
		case <-time.After(giNoMsgTimeout):
			return n
		}
	}
}

func giAssertMsg(t *testing.T, got yat.Msg, path string, data []byte, inbox string) {
	t.Helper()

	if got.Path.String() != path {
		t.Fatalf("path: %q != %q", got.Path.String(), path)
	}
	if !bytes.Equal(got.Data, data) {
		t.Fatalf("data: %q != %q", got.Data, data)
	}
	if got.Inbox.String() != inbox {
		t.Fatalf("inbox: %q != %q", got.Inbox.String(), inbox)
	}
}

func giCloneMsg(m yat.Msg) yat.Msg {
	out := yat.Msg{
		Path: m.Path.Clone(),
		Data: bytes.Clone(m.Data),
	}
	if !m.Inbox.IsZero() {
		out.Inbox = m.Inbox.Clone()
	}
	return out
}

func giFrame(typ byte, body []byte) []byte {
	n := len(body) + giFrameHdrLen
	out := []byte{byte(n), byte(n >> 8), byte(n >> 16), typ}
	return append(out, body...)
}

func giAppendMsgFields(buf []byte, m yat.Msg) []byte {
	buf = protowire.AppendTag(buf, giPathField, protowire.BytesType)
	buf = protowire.AppendBytes(buf, []byte(m.Path.String()))

	if len(m.Data) > 0 {
		buf = protowire.AppendTag(buf, giDataField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, m.Data)
	}
	if !m.Inbox.IsZero() {
		buf = protowire.AppendTag(buf, giInboxField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte(m.Inbox.String()))
	}

	return buf
}

func giPubFrame(m yat.Msg) []byte {
	return giFrame(giPubFrameType, giAppendMsgFields(nil, m))
}

func giSubFrame(t *testing.T, num uint64, sel yat.Sel) []byte {
	t.Helper()

	sf := &wire.SubFrame{
		Num:  num,
		Path: []byte(sel.Path.String()),
	}
	if sel.Group != (yat.Group{}) {
		sf.Group = []byte(sel.Group.String())
	}
	if sel.Limit > 0 {
		sf.Limit = int64(sel.Limit)
	}

	body, err := proto.Marshal(sf)
	if err != nil {
		t.Fatal(err)
	}

	return giFrame(giSubFrameType, body)
}

func giUnsubFrame(t *testing.T, num uint64) []byte {
	t.Helper()

	body, err := proto.Marshal(&wire.UnsubFrame{Num: num})
	if err != nil {
		t.Fatal(err)
	}

	return giFrame(giUnsubFrameType, body)
}

func giMsgFrame(num uint64, m yat.Msg) []byte {
	body := protowire.AppendTag(nil, giNumField, protowire.VarintType)
	body = protowire.AppendVarint(body, num)
	body = giAppendMsgFields(body, m)
	return giFrame(giMsgFrameType, body)
}

func giWriteFrames(t *testing.T, conn net.Conn, frames ...[]byte) {
	t.Helper()

	payload := make([]byte, 0)
	for _, frame := range frames {
		payload = append(payload, frame...)
	}

	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
}

func giReadFrame(t *testing.T, conn net.Conn, timeout time.Duration) (byte, []byte) {
	t.Helper()

	typ, body, err := giReadFrameErr(conn, timeout)
	if err != nil {
		t.Fatal(err)
	}

	return typ, body
}

func giReadAppFrame(t *testing.T, conn net.Conn, timeout time.Duration) (byte, []byte) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			t.Fatal("frame timeout")
		}

		typ, body, err := giReadFrameErr(conn, remaining)
		if err != nil {
			t.Fatal(err)
		}
		if typ == 0 && len(body) == 0 {
			continue
		}

		return typ, body
	}
}

func giExpectNoAppFrame(t *testing.T, conn net.Conn, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return
		}

		typ, body, err := giReadFrameErr(conn, remaining)
		if err != nil {
			if giIsTimeout(err) {
				return
			}
			t.Fatal(err)
		}
		if typ == 0 && len(body) == 0 {
			continue
		}

		t.Fatalf("unexpected frame: type=%d body=%x", typ, body)
	}
}

func giExpectConnClose(t *testing.T, conn net.Conn) {
	t.Helper()

	deadline := time.Now().Add(giMsgTimeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			t.Fatal("expected connection close")
		}

		typ, body, err := giReadFrameErr(conn, remaining)
		if err != nil {
			if giIsTimeout(err) {
				t.Fatal("expected connection close")
			}
			return
		}
		if typ == 0 && len(body) == 0 {
			continue
		}

		t.Fatalf("unexpected frame before close: type=%d body=%x", typ, body)
	}
}

func giReadFrameErr(conn net.Conn, timeout time.Duration) (byte, []byte, error) {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return 0, nil, err
	}
	defer conn.SetReadDeadline(time.Time{})

	hdr := make([]byte, giFrameHdrLen)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return 0, nil, err
	}

	n := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if n < giFrameHdrLen {
		return 0, nil, errors.New("short frame")
	}

	body := make([]byte, n-giFrameHdrLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return 0, nil, err
	}

	return hdr[3], body, nil
}

func giIsTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func giDecodeSharedFields(t *testing.T, body []byte) (uint64, yat.Msg) {
	t.Helper()

	var (
		num uint64
		msg yat.Msg
	)

	for len(body) > 0 {
		fnum, ftyp, nt := protowire.ConsumeTag(body)
		if err := protowire.ParseError(nt); err != nil {
			t.Fatal(err)
		}

		switch fnum {
		case giNumField:
			if ftyp != protowire.VarintType {
				t.Fatalf("field %d type: %v", fnum, ftyp)
			}
			v, nv := protowire.ConsumeVarint(body[nt:])
			if err := protowire.ParseError(nv); err != nil {
				t.Fatal(err)
			}
			num = v
			body = body[nt+nv:]

		case giPathField, giDataField, giInboxField:
			if ftyp != protowire.BytesType {
				t.Fatalf("field %d type: %v", fnum, ftyp)
			}
			v, nv := protowire.ConsumeBytes(body[nt:])
			if err := protowire.ParseError(nv); err != nil {
				t.Fatal(err)
			}
			body = body[nt+nv:]

			switch fnum {
			case giPathField:
				p, _, err := yat.ParsePath(v)
				if err != nil {
					t.Fatal(err)
				}
				msg.Path = p
			case giDataField:
				msg.Data = bytes.Clone(v)
			case giInboxField:
				p, _, err := yat.ParsePath(v)
				if err != nil {
					t.Fatal(err)
				}
				msg.Inbox = p
			}

		default:
			nv := protowire.ConsumeFieldValue(fnum, ftyp, body[nt:])
			if err := protowire.ParseError(nv); err != nil {
				t.Fatal(err)
			}
			body = body[nt+nv:]
		}
	}

	return num, msg
}
