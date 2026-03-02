package yat_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"yat.io/yat"
)

const (
	msgTimeout   = 2 * time.Second
	noMsgTimeout = 150 * time.Millisecond
)

func TestClientServer_SameClient(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, l := startTestServer(t)
		c := newYatClient(t, l)

		msgC, unsub := mustSubscribeClient(t, c, "chat/self")
		t.Cleanup(unsub)
		waitClientReady(t, c, "same")

		if err := c.Publish(yat.Msg{
			Path:  yat.NewPath("chat/self"),
			Data:  []byte("first"),
			Inbox: yat.NewPath("reply/self"),
		}); err != nil {
			t.Fatal(err)
		}

		got := mustRecvClientMsg(t, msgC)
		assertClientMsg(t, got, "chat/self", []byte("first"), "reply/self")

		if err := c.Publish(yat.Msg{
			Path: yat.NewPath("chat/other"),
			Data: []byte("stale"),
		}); err != nil {
			t.Fatal(err)
		}
		mustNoClientMsg(t, msgC)

		unsub()
		if err := c.Publish(yat.Msg{
			Path: yat.NewPath("chat/self"),
			Data: []byte("gone"),
		}); err != nil {
			t.Fatal(err)
		}
		mustNoClientMsg(t, msgC)
	})
}

func TestClientServer_MultipleClientsSameServer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, l := startTestServer(t)

		sub1 := newYatClient(t, l)
		sub2 := newYatClient(t, l)
		nomatch := newYatClient(t, l)
		pub1 := newYatClient(t, l)
		pub2 := newYatClient(t, l)

		waitClientReady(t, sub1, "same-s1")
		waitClientReady(t, sub2, "same-s2")
		waitClientReady(t, nomatch, "same-nomatch")
		waitClientReady(t, pub1, "same-p1")
		waitClientReady(t, pub2, "same-p2")

		sub1C, unsub1 := mustSubscribeClient(t, sub1, "chat/room")
		sub2C, unsub2 := mustSubscribeClient(t, sub2, "chat/room")
		negC, unsubNeg := mustSubscribeClient(t, nomatch, "chat/other")
		t.Cleanup(unsub1)
		t.Cleanup(unsub2)
		t.Cleanup(unsubNeg)
		waitClientReady(t, sub1, "same-s1-sub")
		waitClientReady(t, sub2, "same-s2-sub")
		waitClientReady(t, nomatch, "same-neg-sub")

		if err := pub1.Publish(yat.Msg{
			Path: yat.NewPath("chat/room"),
			Data: []byte("fanout-1"),
		}); err != nil {
			t.Fatal(err)
		}

		if err := pub2.Publish(yat.Msg{
			Path: yat.NewPath("chat/room"),
			Data: []byte("fanout-2"),
		}); err != nil {
			t.Fatal(err)
		}

		got11 := mustRecvClientMsg(t, sub1C)
		got12 := mustRecvClientMsg(t, sub1C)
		got21 := mustRecvClientMsg(t, sub2C)
		got22 := mustRecvClientMsg(t, sub2C)

		for _, got := range []yat.Msg{got11, got12, got21, got22} {
			if got.Path.String() != "chat/room" {
				t.Fatalf("path: %q != %q", got.Path.String(), "chat/room")
			}
		}

		sub1Seen := map[string]bool{
			string(got11.Data): true,
			string(got12.Data): true,
		}
		if !sub1Seen["fanout-1"] || !sub1Seen["fanout-2"] {
			t.Fatalf("sub1 data: %q, %q", got11.Data, got12.Data)
		}

		sub2Seen := map[string]bool{
			string(got21.Data): true,
			string(got22.Data): true,
		}
		if !sub2Seen["fanout-1"] || !sub2Seen["fanout-2"] {
			t.Fatalf("sub2 data: %q, %q", got21.Data, got22.Data)
		}

		mustNoClientMsg(t, negC)
	})
}

func TestClientServer_RouterAndClients(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rr, l := startTestServer(t)

		sub1 := newYatClient(t, l)
		sub2 := newYatClient(t, l)
		pub := newYatClient(t, l)

		waitClientReady(t, sub1, "router-s1")
		waitClientReady(t, sub2, "router-s2")
		waitClientReady(t, pub, "router-pub")

		sub1C, unsub1 := mustSubscribeClient(t, sub1, "router/direct")
		sub2C, unsub2 := mustSubscribeClient(t, sub2, "router/direct")
		t.Cleanup(unsub1)
		t.Cleanup(unsub2)
		waitClientReady(t, sub1, "router-s1-sub")
		waitClientReady(t, sub2, "router-s2-sub")

		if err := rr.Publish(yat.Msg{
			Path:  yat.NewPath("router/direct"),
			Data:  []byte("from-router"),
			Inbox: yat.NewPath("reply/router"),
		}); err != nil {
			t.Fatal(err)
		}

		got1 := mustRecvClientMsg(t, sub1C)
		got2 := mustRecvClientMsg(t, sub2C)
		assertClientMsg(t, got1, "router/direct", []byte("from-router"), "reply/router")
		assertClientMsg(t, got2, "router/direct", []byte("from-router"), "reply/router")

		routerSub1 := make(chan yat.Msg, 8)
		routerSub2 := make(chan yat.Msg, 8)
		unsubR1, err := rr.Subscribe(yat.Sel{Path: yat.NewPath("client/direct")}, func(m yat.Msg) {
			routerSub1 <- cloneMsg(m)
		})
		if err != nil {
			t.Fatal(err)
		}
		unsubR2, err := rr.Subscribe(yat.Sel{Path: yat.NewPath("client/direct")}, func(m yat.Msg) {
			routerSub2 <- cloneMsg(m)
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(unsubR1)
		t.Cleanup(unsubR2)

		if err := pub.Publish(yat.Msg{
			Path:  yat.NewPath("client/direct"),
			Data:  []byte("from-client"),
			Inbox: yat.NewPath("reply/client"),
		}); err != nil {
			t.Fatal(err)
		}

		assertClientMsg(t, mustRecvClientMsg(t, routerSub1), "client/direct", []byte("from-client"), "reply/client")
		assertClientMsg(t, mustRecvClientMsg(t, routerSub2), "client/direct", []byte("from-client"), "reply/client")
	})
}

func TestClientServer_MultipleServersSharedRouter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rr := yat.NewRouter()
		l1 := startTestServerWithRouter(t, rr)
		l2 := startTestServerWithRouter(t, rr)

		sub1 := newYatClient(t, l1)
		sub2 := newYatClient(t, l2)
		pub1 := newYatClient(t, l1)
		pub2 := newYatClient(t, l2)

		waitClientReady(t, sub1, "shared-s1")
		waitClientReady(t, sub2, "shared-s2")
		waitClientReady(t, pub1, "shared-p1")
		waitClientReady(t, pub2, "shared-p2")

		sub1C, unsub1 := mustSubscribeClient(t, sub1, "mesh/topic")
		sub2C, unsub2 := mustSubscribeClient(t, sub2, "mesh/topic")
		t.Cleanup(unsub1)
		t.Cleanup(unsub2)
		waitClientReady(t, sub1, "shared-s1-sub")
		waitClientReady(t, sub2, "shared-s2-sub")

		if err := pub1.Publish(yat.Msg{
			Path:  yat.NewPath("mesh/topic"),
			Data:  []byte("from-srv-1"),
			Inbox: yat.NewPath("reply/1"),
		}); err != nil {
			t.Fatal(err)
		}

		assertClientMsg(t, mustRecvClientMsg(t, sub1C), "mesh/topic", []byte("from-srv-1"), "reply/1")
		assertClientMsg(t, mustRecvClientMsg(t, sub2C), "mesh/topic", []byte("from-srv-1"), "reply/1")

		if err := pub2.Publish(yat.Msg{
			Path:  yat.NewPath("mesh/topic"),
			Data:  []byte("from-srv-2"),
			Inbox: yat.NewPath("reply/2"),
		}); err != nil {
			t.Fatal(err)
		}

		assertClientMsg(t, mustRecvClientMsg(t, sub1C), "mesh/topic", []byte("from-srv-2"), "reply/2")
		assertClientMsg(t, mustRecvClientMsg(t, sub2C), "mesh/topic", []byte("from-srv-2"), "reply/2")

		if err := rr.Publish(yat.Msg{
			Path:  yat.NewPath("mesh/topic"),
			Data:  []byte("from-router"),
			Inbox: yat.NewPath("reply/router"),
		}); err != nil {
			t.Fatal(err)
		}

		assertClientMsg(t, mustRecvClientMsg(t, sub1C), "mesh/topic", []byte("from-router"), "reply/router")
		assertClientMsg(t, mustRecvClientMsg(t, sub2C), "mesh/topic", []byte("from-router"), "reply/router")
	})
}

func newYatClient(t *testing.T, l *pipeListener) *yat.Client {
	t.Helper()

	c, err := yat.NewClient(func(context.Context) (net.Conn, error) {
		return l.Dial()
	}, yat.ClientConfig{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = c.Close()
	})

	return c
}

type pipeListener struct {
	connC chan net.Conn
	doneC chan struct{}
	once  sync.Once
}

type pipeAddr struct{}

func newPipeListener() *pipeListener {
	return &pipeListener{
		connC: make(chan net.Conn, 32),
		doneC: make(chan struct{}),
	}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case <-l.doneC:
		return nil, net.ErrClosed

	case c := <-l.connC:
		return c, nil
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() {
		close(l.doneC)
		for {
			select {
			case c := <-l.connC:
				_ = c.Close()

			default:
				return
			}
		}
	})
	return nil
}

func (l *pipeListener) Addr() net.Addr {
	return pipeAddr{}
}

func (l *pipeListener) Dial() (net.Conn, error) {
	serverConn, clientConn := net.Pipe()
	select {
	case <-l.doneC:
		_ = serverConn.Close()
		_ = clientConn.Close()
		return nil, net.ErrClosed

	case l.connC <- serverConn:
		return clientConn, nil
	}
}

func (pipeAddr) Network() string {
	return "pipe"
}

func (pipeAddr) String() string {
	return "pipe"
}

func startTestServer(t *testing.T) (*yat.Router, *pipeListener) {
	t.Helper()

	rr := yat.NewRouter()
	l := startTestServerWithRouter(t, rr)
	return rr, l
}

func startTestServerWithRouter(t *testing.T, rr *yat.Router) *pipeListener {
	t.Helper()

	srv, err := yat.NewServer(rr, yat.ServerConfig{
		Rules: yat.NoRules(),
	})
	if err != nil {
		t.Fatal(err)
	}

	l := newPipeListener()

	serveC := make(chan error, 1)
	go func() {
		serveC <- srv.Serve(l)
	}()

	t.Cleanup(func() {
		_ = l.Close()
		err := <-serveC
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("serve: %v", err)
		}
	})

	return l
}

func waitClientReady(t *testing.T, c *yat.Client, id string) {
	t.Helper()

	path := "ready/" + id
	readyC, unsub := mustSubscribeClient(t, c, path)
	defer unsub()
	if err := c.Publish(yat.Msg{
		Path: yat.NewPath(path),
		Data: []byte("ready"),
	}); err != nil {
		t.Fatal(err)
	}

	got := mustRecvClientMsg(t, readyC)
	assertClientMsg(t, got, path, []byte("ready"), "")
}

func mustSubscribeClient(t *testing.T, c *yat.Client, path string) (<-chan yat.Msg, func()) {
	t.Helper()

	msgC := make(chan yat.Msg, 64)
	unsub, err := c.Subscribe(yat.Sel{Path: yat.NewPath(path)}, func(m yat.Msg) {
		msgC <- cloneMsg(m)
	})
	if err != nil {
		t.Fatal(err)
	}

	return msgC, unsub
}

func mustRecvClientMsg(t *testing.T, msgC <-chan yat.Msg) yat.Msg {
	t.Helper()

	select {
	case msg := <-msgC:
		return msg

	case <-time.After(msgTimeout):
		t.Fatal("message timeout")
		return yat.Msg{}
	}
}

func mustNoClientMsg(t *testing.T, msgC <-chan yat.Msg) {
	t.Helper()

	select {
	case msg := <-msgC:
		t.Fatalf("unexpected message: path=%q data=%q inbox=%q", msg.Path.String(), msg.Data, msg.Inbox.String())

	case <-time.After(noMsgTimeout):
	}
}

func assertClientMsg(t *testing.T, got yat.Msg, path string, data []byte, inbox string) {
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

func cloneMsg(m yat.Msg) yat.Msg {
	out := yat.Msg{
		Path: m.Path.Clone(),
		Data: bytes.Clone(m.Data),
	}

	if !m.Inbox.IsZero() {
		out.Inbox = m.Inbox.Clone()
	}

	return out
}
