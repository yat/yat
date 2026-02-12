package yat_test

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"google.golang.org/protobuf/proto"

	"yat.io/yat"
	"yat.io/yat/api"
)

const (
	pubFrameType   = 1
	subFrameType   = 2
	unsubFrameType = 3
	msgFrameType   = 4

	frameHdrLen = 4

	msgTimeout   = 2 * time.Second
	noMsgTimeout = 150 * time.Millisecond
)

func TestServerPubSub_SameClient(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, l := startTestServer(t)
		c := newTestClient(t, l)

		c.subscribe(1, "chat/self")
		c.waitReady(1001)

		c.publish("chat/self", []byte("first"), "reply/self")
		msg := c.mustReadMsg()
		assertMsg(t, msg, 1, "chat/self", []byte("first"), "reply/self")

		c.subscribe(1, "chat/other")
		c.waitReady(1002)

		c.publish("chat/self", []byte("stale"), "")
		c.mustNoMsg()

		c.publish("chat/other", []byte("second"), "")
		msg = c.mustReadMsg()
		assertMsg(t, msg, 1, "chat/other", []byte("second"), "")

		c.unsubscribe(1)
		c.publish("chat/other", []byte("gone"), "")
		c.mustNoMsg()
	})
}

func TestServerPubSub_MultipleClients(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, l := startTestServer(t)

		sub1 := newTestClient(t, l)
		sub2 := newTestClient(t, l)
		nomatch := newTestClient(t, l)
		pub := newTestClient(t, l)

		sub1.subscribe(11, "chat/room")
		sub1.waitReady(2001)
		sub2.subscribe(22, "chat/room")
		sub2.waitReady(2002)
		nomatch.subscribe(33, "chat/other")
		nomatch.waitReady(2003)

		pub.publish("chat/room", []byte("fanout"), "")
		msg1 := sub1.mustReadMsg()
		msg2 := sub2.mustReadMsg()
		assertMsg(t, msg1, 11, "chat/room", []byte("fanout"), "")
		assertMsg(t, msg2, 22, "chat/room", []byte("fanout"), "")

		nomatch.mustNoMsg()
		pub.mustNoMsg()
	})
}

func TestServerPubSub_RouterPublish(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rr, l := startTestServer(t)

		sub1 := newTestClient(t, l)
		sub2 := newTestClient(t, l)

		sub1.subscribe(51, "router/direct")
		sub1.waitReady(3001)
		sub2.subscribe(52, "router/direct")
		sub2.waitReady(3002)

		if err := rr.Publish(yat.Msg{
			Path:  yat.NewPath("router/direct"),
			Data:  []byte("from-router"),
			Inbox: yat.NewPath("reply/router"),
		}); err != nil {
			t.Fatal(err)
		}

		msg1 := sub1.mustReadMsg()
		msg2 := sub2.mustReadMsg()
		assertMsg(t, msg1, 51, "router/direct", []byte("from-router"), "reply/router")
		assertMsg(t, msg2, 52, "router/direct", []byte("from-router"), "reply/router")

		if err := rr.Publish(yat.Msg{
			Path: yat.NewPath("router/other"),
			Data: []byte("no-match"),
		}); err != nil {
			t.Fatal(err)
		}

		sub1.mustNoMsg()
		sub2.mustNoMsg()
	})
}

type testClient struct {
	t *testing.T
	c net.Conn
}

func newTestClient(t *testing.T, l *pipeListener) *testClient {
	t.Helper()

	c, err := l.Dial()
	if err != nil {
		t.Fatal(err)
	}

	tc := &testClient{
		t: t,
		c: c,
	}

	t.Cleanup(func() {
		_ = c.Close()
	})

	return tc
}

func (tc *testClient) waitReady(num uint64) {
	tc.t.Helper()

	path := "ready/" + strconv.FormatUint(num, 10)
	tc.subscribe(num, path)
	tc.publish(path, []byte("ready"), "")
	msg := tc.mustReadMsg()
	assertMsg(tc.t, msg, num, path, []byte("ready"), "")
	tc.unsubscribe(num)
}

func (tc *testClient) publish(path string, data []byte, inbox string) {
	tc.t.Helper()

	f := &api.PubFrame{
		Path: []byte(path),
		Data: data,
	}

	if inbox != "" {
		f.Inbox = []byte(inbox)
	}

	tc.writeProtoFrame(pubFrameType, f)
}

func (tc *testClient) subscribe(num uint64, path string) {
	tc.t.Helper()
	tc.writeProtoFrame(subFrameType, &api.SubFrame{
		Num:  num,
		Path: []byte(path),
	})
}

func (tc *testClient) unsubscribe(num uint64) {
	tc.t.Helper()
	tc.writeProtoFrame(unsubFrameType, &api.UnsubFrame{
		Num: num,
	})
}

func (tc *testClient) writeProtoFrame(typ byte, m proto.Message) {
	tc.t.Helper()

	body, err := proto.Marshal(m)
	if err != nil {
		tc.t.Fatal(err)
	}

	tc.writeFrame(typ, body)
}

func (tc *testClient) writeFrame(typ byte, body []byte) {
	tc.t.Helper()

	n := frameHdrLen + len(body)
	frame := make([]byte, n)
	frame[0] = byte(n)
	frame[1] = byte(n >> 8)
	frame[2] = byte(n >> 16)
	frame[3] = typ
	copy(frame[frameHdrLen:], body)

	if _, err := tc.c.Write(frame); err != nil {
		tc.t.Fatal(err)
	}
}

func (tc *testClient) mustReadMsg() *api.MsgFrame {
	tc.t.Helper()

	msg, err := tc.readMsg(msgTimeout)
	if err != nil {
		tc.t.Fatal(err)
	}

	return msg
}

func (tc *testClient) mustNoMsg() {
	tc.t.Helper()

	_, err := tc.readMsg(noMsgTimeout)
	if err == nil {
		tc.t.Fatal("unexpected message")
	}

	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		tc.t.Fatalf("error: %v", err)
	}
}

func (tc *testClient) readMsg(timeout time.Duration) (*api.MsgFrame, error) {
	msg := &api.MsgFrame{}

	if err := tc.c.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	defer tc.c.SetReadDeadline(time.Time{})

	for {
		typ, body, err := readFrame(tc.c)
		if err != nil {
			return nil, err
		}

		if typ != msgFrameType {
			continue
		}

		if err := proto.Unmarshal(body, msg); err != nil {
			return nil, err
		}

		return msg, nil
	}
}

func readFrame(r io.Reader) (typ byte, body []byte, err error) {
	var hdr [frameHdrLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}

	n := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if n < frameHdrLen {
		return 0, nil, errors.New("short frame")
	}

	body = make([]byte, n-frameHdrLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}

	return hdr[3], body, nil
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
	srv, err := yat.NewServer(rr, yat.ServerConfig{})
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

	return rr, l
}

func assertMsg(t *testing.T, got *api.MsgFrame, num uint64, path string, data []byte, inbox string) {
	t.Helper()

	if got.GetNum() != num {
		t.Fatalf("num: %d != %d", got.GetNum(), num)
	}
	if string(got.GetPath()) != path {
		t.Fatalf("path: %q != %q", got.GetPath(), path)
	}
	if !bytes.Equal(got.GetData(), data) {
		t.Fatalf("data: %q != %q", got.GetData(), data)
	}
	if string(got.GetInbox()) != inbox {
		t.Fatalf("inbox: %q != %q", got.GetInbox(), inbox)
	}
}
