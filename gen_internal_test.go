//go:build !human

package yat

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

func TestGrant_allow(t *testing.T) {
	grant := Grant{
		Path:    NewPath("a/**"),
		Actions: []Action{ActionPub},
	}

	if !grant.allow(NewPath("a/b"), ActionPub) {
		t.Fatal("no match")
	}
	if grant.allow(NewPath("a/b"), ActionSub) {
		t.Fatal("unexpected action match")
	}
	if grant.allow(NewPath("b/a"), ActionPub) {
		t.Fatal("unexpected path match")
	}
	if (Grant{}).allow(NewPath("a/b"), ActionPub) {
		t.Fatal("zero grant matched")
	}
}

func TestSPIFFESpec_match(t *testing.T) {
	tcs := []struct {
		name string
		spec SPIFFESpec
		p    Principal
		want bool
	}{
		{
			name: "nil conn",
			spec: SPIFFESpec{Domain: "trust-domain"},
			p:    Principal{},
		},
		{
			name: "conn without state",
			spec: SPIFFESpec{Domain: "trust-domain"},
			p:    Principal{Conn: authNoStateConn{}},
		},
		{
			name: "no verified chains",
			spec: SPIFFESpec{Domain: "trust-domain"},
			p: Principal{Conn: authStateConn{
				state: tls.ConnectionState{},
			}},
		},
		{
			name: "empty verified chain",
			spec: SPIFFESpec{Domain: "trust-domain"},
			p: Principal{Conn: authStateConn{
				state: tls.ConnectionState{
					VerifiedChains: [][]*x509.Certificate{{}},
				},
			}},
		},
		{
			name: "no uri sans",
			spec: SPIFFESpec{Domain: "trust-domain"},
			p:    newAuthPrincipal(),
		},
		{
			name: "multiple uri sans",
			spec: SPIFFESpec{Domain: "trust-domain"},
			p: newAuthPrincipal(
				mustParseAuthURL(t, "spiffe://trust-domain/a"),
				mustParseAuthURL(t, "spiffe://trust-domain/b"),
			),
		},
		{
			name: "wrong scheme",
			spec: SPIFFESpec{Domain: "trust-domain"},
			p:    newAuthPrincipal(mustParseAuthURL(t, "https://trust-domain/a")),
		},
		{
			name: "query rejected",
			spec: SPIFFESpec{Domain: "trust-domain"},
			p:    newAuthPrincipal(mustParseAuthURL(t, "spiffe://trust-domain/a?a=b")),
		},
		{
			name: "force query rejected",
			spec: SPIFFESpec{Domain: "trust-domain"},
			p:    newAuthPrincipal(mustParseAuthURL(t, "spiffe://trust-domain/a?")),
		},
		{
			name: "userinfo rejected",
			spec: SPIFFESpec{Domain: "trust-domain"},
			p:    newAuthPrincipal(mustParseAuthURL(t, "spiffe://user@trust-domain/a")),
		},
		{
			name: "invalid trust domain rejected",
			spec: SPIFFESpec{Domain: "trust-domain"},
			p:    newAuthPrincipal(mustParseAuthURL(t, "spiffe://trust-domain:443/a")),
		},
		{
			name: "wild path rejected",
			spec: SPIFFESpec{Domain: "trust-domain"},
			p:    newAuthPrincipal(mustParseAuthURL(t, "spiffe://trust-domain/*")),
		},
		{
			name: "domain mismatch",
			spec: SPIFFESpec{Domain: "other-domain"},
			p:    newAuthPrincipal(mustParseAuthURL(t, "spiffe://trust-domain/a")),
		},
		{
			name: "path mismatch",
			spec: SPIFFESpec{Domain: "trust-domain", Path: NewPath("a/b")},
			p:    newAuthPrincipal(mustParseAuthURL(t, "spiffe://trust-domain/a/c")),
		},
		{
			name: "pathless id matches domain rule",
			spec: SPIFFESpec{Domain: "trust-domain"},
			p:    newAuthPrincipal(mustParseAuthURL(t, "spiffe://trust-domain")),
			want: true,
		},
		{
			name: "pathful id matches domain rule",
			spec: SPIFFESpec{Domain: "trust-domain"},
			p:    newAuthPrincipal(mustParseAuthURL(t, "spiffe://trust-domain/a/b")),
			want: true,
		},
		{
			name: "exact path match",
			spec: SPIFFESpec{Domain: "trust-domain", Path: NewPath("a/b")},
			p:    newAuthPrincipal(mustParseAuthURL(t, "spiffe://trust-domain/a/b")),
			want: true,
		},
		{
			name: "wildcard path match",
			spec: SPIFFESpec{Domain: "trust-domain", Path: NewPath("a/*")},
			p:    newAuthPrincipal(mustParseAuthURL(t, "spiffe://trust-domain/a/b")),
			want: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.spec.match(tc.p); got != tc.want {
				t.Fatalf("match: %t != %t", got, tc.want)
			}
		})
	}
}

func TestRuleSet_Compile_clonesGrants(t *testing.T) {
	rs := &RuleSet{rr: []Rule{{
		Grants: []Grant{{
			Path:    NewPath("a"),
			Actions: []Action{ActionPub},
		}},
	}}}

	allow := rs.Compile(Principal{})

	rs.rr[0].Grants[0].Path = NewPath("b")
	rs.rr[0].Grants[0].Actions[0] = ActionSub

	if !allow(NewPath("a"), ActionPub) {
		t.Fatal("compiled grant changed")
	}
	if allow(NewPath("b"), ActionPub) {
		t.Fatal("unexpected mutated path grant")
	}
	if allow(NewPath("a"), ActionSub) {
		t.Fatal("unexpected mutated action grant")
	}
}

type authStateConn struct {
	state tls.ConnectionState
}

func (c authStateConn) ConnectionState() tls.ConnectionState { return c.state }
func (authStateConn) Read([]byte) (int, error)               { return 0, io.EOF }
func (authStateConn) Write(p []byte) (int, error)            { return len(p), nil }
func (authStateConn) Close() error                           { return nil }
func (authStateConn) LocalAddr() net.Addr                    { return testAddr("local") }
func (authStateConn) RemoteAddr() net.Addr                   { return testAddr("remote") }
func (authStateConn) SetDeadline(time.Time) error            { return nil }
func (authStateConn) SetReadDeadline(time.Time) error        { return nil }
func (authStateConn) SetWriteDeadline(time.Time) error       { return nil }

type authNoStateConn struct{}

func (authNoStateConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (authNoStateConn) Write(p []byte) (int, error)      { return len(p), nil }
func (authNoStateConn) Close() error                     { return nil }
func (authNoStateConn) LocalAddr() net.Addr              { return testAddr("local") }
func (authNoStateConn) RemoteAddr() net.Addr             { return testAddr("remote") }
func (authNoStateConn) SetDeadline(time.Time) error      { return nil }
func (authNoStateConn) SetReadDeadline(time.Time) error  { return nil }
func (authNoStateConn) SetWriteDeadline(time.Time) error { return nil }

func newAuthPrincipal(uris ...*url.URL) Principal {
	return Principal{Conn: authStateConn{
		state: tls.ConnectionState{
			VerifiedChains: [][]*x509.Certificate{{
				{URIs: uris},
			}},
		},
	}}
}

func mustParseAuthURL(t *testing.T, raw string) *url.URL {
	t.Helper()

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	return u
}

func TestClient_NewClient(t *testing.T) {
	t.Run("nil dial", func(t *testing.T) {
		_, err := NewClient(nil, ClientConfig{})
		if err == nil {
			t.Fatal("no error")
		}
	})
}

func TestClient_Close(t *testing.T) {
	t.Run("already closed", func(t *testing.T) {
		c := newBareClient()
		close(c.doneC)
		close(c.connC)

		if err := c.Close(); !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	})

	t.Run("closes all sub done channels", func(t *testing.T) {
		c := newBareClient()

		sub1, err := c.Subscribe(Sel{Path: NewPath("a")}, func(Msg) {})
		if err != nil {
			t.Fatal(err)
		}
		sub2, err := c.Subscribe(Sel{Path: NewPath("b")}, func(Msg) {})
		if err != nil {
			t.Fatal(err)
		}

		select {
		case <-sub1.Done():
			t.Fatal("sub1 done closed early")
		default:
		}
		select {
		case <-sub2.Done():
			t.Fatal("sub2 done closed early")
		default:
		}

		close(c.connC)
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}

		select {
		case <-sub1.Done():
		default:
			t.Fatal("sub1 done not closed")
		}
		select {
		case <-sub2.Done():
		default:
			t.Fatal("sub2 done not closed")
		}
	})
}

func TestClient_Publish_validationAndClosed(t *testing.T) {
	c := newBareClient()

	if err := c.Publish(Msg{}); !errors.Is(err, errEmptyPath) {
		t.Fatalf("empty path: %v", err)
	}
	if err := c.Publish(Msg{Path: NewPath("*")}); !errors.Is(err, errWildPath) {
		t.Fatalf("wild path: %v", err)
	}
	if err := c.Publish(Msg{Path: NewPath("path"), Inbox: NewPath("*")}); !errors.Is(err, errWildInbox) {
		t.Fatalf("wild inbox: %v", err)
	}

	tooLongData := make([]byte, MaxFrameLen)
	if err := c.Publish(Msg{Path: NewPath("path"), Data: tooLongData}); !errors.Is(err, errLongFrame) {
		t.Fatalf("long frame: %v", err)
	}

	close(c.doneC)
	if err := c.Publish(Msg{Path: NewPath("path")}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed: %v", err)
	}
}

func TestClient_Subscribe_validationAndUnsubPaths(t *testing.T) {
	t.Run("validation", func(t *testing.T) {
		c := newBareClient()

		if _, err := c.Subscribe(Sel{}, func(Msg) {}); !errors.Is(err, errEmptyPath) {
			t.Fatalf("empty path: %v", err)
		}
		if _, err := c.Subscribe(Sel{Path: NewPath("path"), Limit: -1}, func(Msg) {}); !errors.Is(err, errLimitRange) {
			t.Fatalf("negative limit: %v", err)
		}
		if _, err := c.Subscribe(Sel{Path: NewPath("path"), Limit: MaxLimit + 1}, func(Msg) {}); !errors.Is(err, errLimitRange) {
			t.Fatalf("limit over max: %v", err)
		}
		if _, err := c.Subscribe(Sel{Path: NewPath("path")}, nil); !errors.Is(err, errNilCallback) {
			t.Fatalf("nil callback: %v", err)
		}

		close(c.doneC)
		if _, err := c.Subscribe(Sel{Path: NewPath("path")}, func(Msg) {}); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("closed: %v", err)
		}
	})

	t.Run("signal channel already full", func(t *testing.T) {
		c := newBareClient()
		fillClientSignal(c)

		sub, err := c.Subscribe(Sel{Path: NewPath("path")}, func(Msg) {})
		if err != nil {
			t.Fatal(err)
		}
		if len(c.wbufC) != 1 {
			t.Fatalf("len(wbufC): %d != 1", len(c.wbufC))
		}

		sub.Cancel()
		if len(c.wbufC) != 1 {
			t.Fatalf("len(wbufC): %d != 1", len(c.wbufC))
		}
	})

	t.Run("unsub after close is a no-op", func(t *testing.T) {
		c := newBareClient()
		sub, err := c.Subscribe(Sel{Path: NewPath("path")}, func(Msg) {})
		if err != nil {
			t.Fatal(err)
		}
		if len(c.subs) != 1 {
			t.Fatalf("len(subs): %d != 1", len(c.subs))
		}

		close(c.doneC)
		sub.Cancel()
		if len(c.subs) != 1 {
			t.Fatalf("len(subs): %d != 1", len(c.subs))
		}
	})

	t.Run("done closes on cancel", func(t *testing.T) {
		c := newBareClient()
		sub, err := c.Subscribe(Sel{Path: NewPath("path")}, func(Msg) {})
		if err != nil {
			t.Fatal(err)
		}

		select {
		case <-sub.Done():
			t.Fatal("done closed early")
		default:
		}

		sub.Cancel()

		select {
		case <-sub.Done():
		default:
			t.Fatal("done not closed")
		}
	})
}

func TestClient_readFrames(t *testing.T) {
	t.Run("short frame", func(t *testing.T) {
		c := newBareClient()
		conn := newTestConnWithBytes([]byte{3, 0, 0, msgFrameType})
		err := c.readFrames(context.Background(), discardLogger, conn)
		if !errors.Is(err, errShortFrame) {
			t.Fatal(err)
		}
	})

	t.Run("unknown frame discard fails on short body", func(t *testing.T) {
		c := newBareClient()
		unknown := newUnknownFrame(99, []byte{1, 2})
		unknown = unknown[:len(unknown)-1]

		err := c.readFrames(context.Background(), discardLogger, newTestConnWithBytes(unknown))
		if !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
	})

	t.Run("unknown frame is discarded, known msg is handled", func(t *testing.T) {
		c := newBareClient()
		msgC := make(chan Msg, 1)
		c.subs[7] = &clientSub{
			Do: func(m Msg) { msgC <- m },
		}

		msg := Msg{Path: NewPath("a"), Data: []byte("hi"), Inbox: NewPath("inbox")}
		wire := appendFrames(
			newUnknownFrame(99, []byte{1, 2, 3}),
			newMsgFrame(7, msg),
		)

		err := c.readFrames(context.Background(), discardLogger, newTestConnWithBytes(wire))
		if !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}

		got := <-msgC
		if got.Path.String() != "a" {
			t.Fatalf("path: %q != %q", got.Path.String(), "a")
		}
		if !bytes.Equal(got.Data, []byte("hi")) {
			t.Fatalf("data: %q != %q", got.Data, "hi")
		}
		if got.Inbox.String() != "inbox" {
			t.Fatalf("inbox: %q != %q", got.Inbox.String(), "inbox")
		}
	})

	t.Run("known msg with short body fails read", func(t *testing.T) {
		c := newBareClient()
		wire := newMsgFrame(1, Msg{Path: NewPath("path")})
		wire = wire[:len(wire)-1]

		err := c.readFrames(context.Background(), discardLogger, newTestConnWithBytes(wire))
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatal(err)
		}
	})

	t.Run("handler error is returned", func(t *testing.T) {
		c := newBareClient()
		wire := appendFrame(nil, msgFrameType, func(b []byte) []byte { return b })

		err := c.readFrames(context.Background(), discardLogger, newTestConnWithBytes(wire))
		if !errors.Is(err, errEmptyPath) {
			t.Fatal(err)
		}
	})

}

func TestClient_handleMsg(t *testing.T) {
	t.Run("parse failure", func(t *testing.T) {
		c := newBareClient()
		err := c.handleMsg(context.Background(), discardLogger, []byte{0x80})
		if err == nil {
			t.Fatal("no error")
		}
	})

	t.Run("wild inbox is accepted", func(t *testing.T) {
		c := newBareClient()
		var got Msg
		c.subs[1] = &clientSub{
			Sel: Sel{Path: NewPath("a")},
			Do:  func(m Msg) { got = m },
		}

		body := newMsgFrame(1, Msg{Path: NewPath("a"), Inbox: NewPath("*")})[frameHdrLen:]
		if err := c.handleMsg(context.Background(), discardLogger, body); err != nil {
			t.Fatal(err)
		}
		if got.Path.String() != "a" {
			t.Fatalf("path: %q != %q", got.Path.String(), "a")
		}
		if got.Inbox.String() != "*" {
			t.Fatalf("inbox: %q != %q", got.Inbox.String(), "*")
		}
	})

	t.Run("limit removes local sub after final delivery", func(t *testing.T) {
		c := newBareClient()
		var delivered int
		doneC := make(chan struct{})
		c.subs[1] = &clientSub{
			Sel:   Sel{Path: NewPath("a"), Limit: 1},
			Do:    func(Msg) { delivered++ },
			doneC: doneC,
			unsub: func() {
				delete(c.subs, 1)
				close(doneC)
			},
		}

		body := newMsgFrame(1, Msg{Path: NewPath("a"), Data: []byte("hi")})[frameHdrLen:]

		if err := c.handleMsg(context.Background(), discardLogger, body); err != nil {
			t.Fatal(err)
		}
		if delivered != 1 {
			t.Fatalf("delivered: %d != %d", delivered, 1)
		}
		if _, ok := c.subs[1]; ok {
			t.Fatal("subscription not removed")
		}

		if err := c.handleMsg(context.Background(), discardLogger, body); err != nil {
			t.Fatal(err)
		}
		if delivered != 1 {
			t.Fatalf("delivered: %d != %d", delivered, 1)
		}
	})

	t.Run("limit closes done", func(t *testing.T) {
		c := newBareClient()
		sub, err := c.Subscribe(Sel{Path: NewPath("a"), Limit: 1}, func(Msg) {})
		if err != nil {
			t.Fatal(err)
		}

		select {
		case <-sub.Done():
			t.Fatal("done closed early")
		default:
		}

		body := newMsgFrame(1, Msg{Path: NewPath("a"), Data: []byte("hi")})[frameHdrLen:]
		if err := c.handleMsg(context.Background(), discardLogger, body); err != nil {
			t.Fatal(err)
		}

		select {
		case <-sub.Done():
		default:
			t.Fatal("done not closed")
		}
	})
}

func TestClient_writeFrames(t *testing.T) {
	t.Run("write failure", func(t *testing.T) {
		c := newBareClient()
		c.wbuf = []byte("payload")
		fillClientSignal(c)

		wantErr := errors.New("write failed")
		conn := &testConn{writeErr: wantErr}

		err := c.writeFrames(context.Background(), discardLogger, conn)
		if !errors.Is(err, wantErr) {
			t.Fatal(err)
		}
		if !conn.closed.Load() {
			t.Fatal("expected close")
		}
	})

	t.Run("context canceled still flushes current buffer", func(t *testing.T) {
		c := newBareClient()
		c.wbuf = []byte("payload")

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		conn := &testConn{}
		err := c.writeFrames(ctx, discardLogger, conn)
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		if !bytes.Equal(conn.wrote(), []byte("payload")) {
			t.Fatalf("wrote: %q != %q", conn.wrote(), []byte("payload"))
		}
		if !conn.closed.Load() {
			t.Fatal("expected close")
		}
	})

}

func TestClient_keepalive(t *testing.T) {
	t.Run("injects keepalive when writer is idle", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			c := newBareClient()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			errC := make(chan error, 1)
			go func() {
				errC <- c.keepalive(ctx)
			}()

			synctest.Wait()
			time.Sleep(1 * time.Second)
			synctest.Wait()
			if !bytes.Equal(c.wbuf, []byte{4, 0, 0, 0}) {
				t.Fatalf("wbuf: %x != %x", c.wbuf, []byte{4, 0, 0, 0})
			}
			if len(c.wbufC) != 1 {
				t.Fatalf("len(wbufC): %d != 1", len(c.wbufC))
			}

			cancel()
			if err := <-errC; !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		})
	})

	t.Run("does not inject keepalive while outbound buffer is non-empty", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			c := newBareClient()
			c.wbuf = []byte("pending")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			errC := make(chan error, 1)
			go func() {
				errC <- c.keepalive(ctx)
			}()

			synctest.Wait()
			time.Sleep(1 * time.Second)
			synctest.Wait()
			if !bytes.Equal(c.wbuf, []byte("pending")) {
				t.Fatalf("wbuf: %q != %q", c.wbuf, []byte("pending"))
			}
			if len(c.wbufC) != 0 {
				t.Fatalf("len(wbufC): %d != 0", len(c.wbufC))
			}

			cancel()
			if err := <-errC; !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		})
	})

	t.Run("signal send is dropped when channel is already full", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			c := newBareClient()
			fillClientSignal(c)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			errC := make(chan error, 1)
			go func() {
				errC <- c.keepalive(ctx)
			}()

			synctest.Wait()
			time.Sleep(1 * time.Second)
			synctest.Wait()
			if !bytes.Equal(c.wbuf, []byte{4, 0, 0, 0}) {
				t.Fatalf("wbuf: %x != %x", c.wbuf, []byte{4, 0, 0, 0})
			}
			if len(c.wbufC) != 1 {
				t.Fatalf("len(wbufC): %d != 1", len(c.wbufC))
			}

			cancel()
			if err := <-errC; !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		})
	})
}

func TestClient_connect(t *testing.T) {
	t.Run("retries after dial failures", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			c := newBareClient()
			t.Cleanup(func() {
				select {
				case <-c.doneC:
				default:
					close(c.doneC)
				}
				<-c.connC
			})

			var calls atomic.Int32

			go c.connect(func(context.Context) (net.Conn, error) {
				calls.Add(1)
				return nil, errors.New("dial failed")
			})

			synctest.Wait()
			time.Sleep(500 * time.Millisecond)
			synctest.Wait()
			if got := calls.Load(); got < 2 {
				t.Fatalf("calls: %d < 2", got)
			}
		})
	})

	t.Run("serve errors trigger redial loop", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			c := newBareClient()
			t.Cleanup(func() {
				select {
				case <-c.doneC:
				default:
					close(c.doneC)
				}
				<-c.connC
			})

			var calls atomic.Int32

			go c.connect(func(context.Context) (net.Conn, error) {
				calls.Add(1)
				server, client := net.Pipe()
				go func() {
					_ = server.Close()
				}()
				return client, nil
			})

			synctest.Wait()
			time.Sleep(500 * time.Millisecond)
			synctest.Wait()
			if got := calls.Load(); got < 2 {
				t.Fatalf("calls: %d < 2", got)
			}
		})
	})

	t.Run("reconnect replays subscriptions", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			c := newBareClient()
			t.Cleanup(func() {
				select {
				case <-c.doneC:
				default:
					close(c.doneC)
				}
				<-c.connC
			})

			subPath := NewPath("path")
			if _, err := c.Subscribe(Sel{Path: subPath}, func(Msg) {}); err != nil {
				t.Fatal(err)
			}

			connC := make(chan *testConn, 4)
			go c.connect(func(context.Context) (net.Conn, error) {
				tc := &testConn{}
				connC <- tc
				return tc, nil
			})

			first := <-connC
			synctest.Wait()
			if !bytes.Equal(first.wrote(), newSubFrame(1, subPath)) {
				t.Fatalf("first write: %x != %x", first.wrote(), newSubFrame(1, subPath))
			}

			time.Sleep(500 * time.Millisecond)
			second := <-connC
			synctest.Wait()
			if !bytes.Equal(second.wrote(), newSubFrame(1, subPath)) {
				t.Fatalf("second write: %x != %x", second.wrote(), newSubFrame(1, subPath))
			}
		})
	})

	t.Run("reconnect replays grouped subscriptions", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			c := newBareClient()
			t.Cleanup(func() {
				select {
				case <-c.doneC:
				default:
					close(c.doneC)
				}
				<-c.connC
			})

			subSel := Sel{
				Path:  NewPath("path"),
				Group: NewGroup("workers"),
			}
			if _, err := c.Subscribe(subSel, func(Msg) {}); err != nil {
				t.Fatal(err)
			}

			connC := make(chan *testConn, 4)
			go c.connect(func(context.Context) (net.Conn, error) {
				tc := &testConn{}
				connC <- tc
				return tc, nil
			})

			first := <-connC
			synctest.Wait()
			if !bytes.Equal(first.wrote(), newSubFrameSel(1, subSel)) {
				t.Fatalf("first write: %x != %x", first.wrote(), newSubFrameSel(1, subSel))
			}

			time.Sleep(500 * time.Millisecond)
			second := <-connC
			synctest.Wait()
			if !bytes.Equal(second.wrote(), newSubFrameSel(1, subSel)) {
				t.Fatalf("second write: %x != %x", second.wrote(), newSubFrameSel(1, subSel))
			}
		})
	})

}

var discardLogger = ClientConfig{}.withDefaults().Logger

type testAddr string

func (a testAddr) Network() string { return "test" }
func (a testAddr) String() string  { return string(a) }

type testConn struct {
	r io.Reader

	writeErr error
	writeBuf bytes.Buffer
	closed   atomic.Bool
}

func (c *testConn) Read(p []byte) (int, error) {
	if c.r == nil {
		return 0, io.EOF
	}
	return c.r.Read(p)
}

func (c *testConn) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return c.writeBuf.Write(p)
}

func (c *testConn) Close() error {
	c.closed.Store(true)
	return nil
}

func (c *testConn) LocalAddr() net.Addr              { return testAddr("local") }
func (c *testConn) RemoteAddr() net.Addr             { return testAddr("remote") }
func (c *testConn) SetDeadline(time.Time) error      { return nil }
func (c *testConn) SetReadDeadline(time.Time) error  { return nil }
func (c *testConn) SetWriteDeadline(time.Time) error { return nil }
func (c *testConn) wrote() []byte                    { return bytes.Clone(c.writeBuf.Bytes()) }

func newTestConnWithBytes(b []byte) *testConn {
	return &testConn{r: bytes.NewReader(b)}
}

func newBareClient() *Client {
	return &Client{
		config: ClientConfig{}.withDefaults(),
		subs:   map[uint64]*clientSub{},
		wbufC:  make(chan struct{}, 1),
		doneC:  make(chan struct{}),
		connC:  make(chan struct{}),
	}
}

func newBareServerConn(conn net.Conn) *serverConn {
	return &serverConn{
		allow: AllowAll().Compile(Principal{}),
		subs:  map[uint64]*rent{},
		wbufC: make(chan struct{}, 1),
		Conn:  conn,
	}
}

func newSubFrame(num uint64, path Path) []byte {
	return newSubFrameSel(num, Sel{Path: path})
}

func newSubFrameSel(num uint64, sel Sel) []byte {
	return appendSubFrame(nil, num, sel)
}

func newUnsubFrame(num uint64) []byte {
	return appendFrame(nil, unsubFrameType, func(b []byte) []byte {
		b = protowire.AppendTag(b, numField, protowire.VarintType)
		b = protowire.AppendVarint(b, num)
		return b
	})
}

func newMsgFrame(num uint64, m Msg) []byte {
	return appendFrame(nil, msgFrameType, func(b []byte) []byte {
		b = protowire.AppendTag(b, numField, protowire.VarintType)
		b = protowire.AppendVarint(b, num)
		return appendMsgFields(b, m)
	})
}

func newUnknownFrame(typ byte, body []byte) []byte {
	return appendFrame(nil, typ, func(b []byte) []byte {
		return append(b, body...)
	})
}

func appendFrames(frames ...[]byte) (out []byte) {
	for _, f := range frames {
		out = append(out, f...)
	}
	return out
}

func fillClientSignal(c *Client) {
	select {
	case c.wbufC <- struct{}{}:
	default:
	}
}

func fillServerSignal(c *serverConn) {
	select {
	case c.wbufC <- struct{}{}:
	default:
	}
}

func Test_frameHdr(t *testing.T) {
	const (
		typ = byte(0x7f)
		len = 0x00a1b2
	)

	h := frameHdr(uint32(typ)<<24 | len)

	if got := h.Len(); got != len {
		t.Fatalf("Len: %d != %d", got, len)
	}

	if got := h.BodyLen(); got != len-4 {
		t.Fatalf("BodyLen: %d != %d", got, len-4)
	}

	if got := h.Type(); got != typ {
		t.Fatalf("Type: %d != %d", got, typ)
	}
}

func Test_readFrameHdr(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		// len=u24le (0x001234), type=5
		src := []byte{0x34, 0x12, 0x00, 0x05}

		h, err := readFrameHdr(bytes.NewReader(src))
		if err != nil {
			t.Fatal(err)
		}

		if got := h.Len(); got != 0x001234 {
			t.Fatalf("Len: %d != %d", got, 0x001234)
		}

		if got := h.Type(); got != 5 {
			t.Fatalf("Type: %d != %d", got, 5)
		}
	})

	t.Run("short", func(t *testing.T) {
		_, err := readFrameHdr(bytes.NewReader([]byte{1, 2, 3}))
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatal(err)
		}
	})
}

func Test_appendFrameBytes(t *testing.T) {
	prefix := []byte{0xaa, 0xbb}
	body := []byte("pub")

	got := appendFrameBytes(bytes.Clone(prefix), pubFrameType, body)
	want := appendFrame(bytes.Clone(prefix), pubFrameType, func(b []byte) []byte {
		return append(b, body...)
	})

	if !bytes.Equal(got, want) {
		t.Fatalf("frame: %x != %x", got, want)
	}
}

func Test_appendSubFrame_limit(t *testing.T) {
	tcs := []struct {
		Name      string
		Sel       Sel
		WantLimit int64
	}{
		{
			Name:      "zero limit omitted",
			Sel:       Sel{Path: NewPath("path")},
			WantLimit: 0,
		},
		{
			Name:      "positive limit encoded",
			Sel:       Sel{Path: NewPath("path"), Group: NewGroup("group"), Limit: 5},
			WantLimit: 5,
		},
		{
			Name:      "negative limit clamped",
			Sel:       Sel{Path: NewPath("path"), Limit: -4},
			WantLimit: 0,
		},
		{
			Name:      "over max limit clamped",
			Sel:       Sel{Path: NewPath("path"), Limit: MaxLimit + 10},
			WantLimit: MaxLimit,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.Name, func(t *testing.T) {
			frame := appendSubFrame(nil, 7, tc.Sel)
			raw, n := protowire.ConsumeFixed32(frame)
			if n < 0 {
				t.Fatal(protowire.ParseError(n))
			}
			if got := frameHdr(raw); got.Type() != subFrameType {
				t.Fatalf("type: %d != %d", got.Type(), subFrameType)
			}

			var (
				gotNum   uint64
				gotPath  []byte
				gotGroup []byte
				gotLimit int64
			)

			for body := frame[frameHdrLen:]; len(body) > 0; {
				fn, typ, nt := protowire.ConsumeTag(body)
				if nt < 0 {
					t.Fatal(protowire.ParseError(nt))
				}

				switch fn {
				case numField:
					if typ != protowire.VarintType {
						t.Fatalf("num type: %v", typ)
					}
					v, nv := protowire.ConsumeVarint(body[nt:])
					if nv < 0 {
						t.Fatal(protowire.ParseError(nv))
					}
					gotNum = v
					body = body[nt+nv:]

				case pathField:
					if typ != protowire.BytesType {
						t.Fatalf("path type: %v", typ)
					}
					v, nv := protowire.ConsumeBytes(body[nt:])
					if nv < 0 {
						t.Fatal(protowire.ParseError(nv))
					}
					gotPath = v
					body = body[nt+nv:]

				case 3:
					if typ != protowire.BytesType {
						t.Fatalf("group type: %v", typ)
					}
					v, nv := protowire.ConsumeBytes(body[nt:])
					if nv < 0 {
						t.Fatal(protowire.ParseError(nv))
					}
					gotGroup = v
					body = body[nt+nv:]

				case 4:
					if typ != protowire.VarintType {
						t.Fatalf("limit type: %v", typ)
					}
					v, nv := protowire.ConsumeVarint(body[nt:])
					if nv < 0 {
						t.Fatal(protowire.ParseError(nv))
					}
					gotLimit = int64(v)
					body = body[nt+nv:]

				default:
					t.Fatalf("unexpected field: %d", fn)
				}
			}

			if gotNum != 7 {
				t.Fatalf("num: %d != %d", gotNum, 7)
			}
			if !bytes.Equal(gotPath, tc.Sel.Path.p) {
				t.Fatalf("path: %q != %q", gotPath, tc.Sel.Path.p)
			}

			var wantGroup []byte
			if tc.Sel.Group != (Group{}) {
				wantGroup = []byte(tc.Sel.Group.String())
			}
			if !bytes.Equal(gotGroup, wantGroup) {
				t.Fatalf("group: %q != %q", gotGroup, wantGroup)
			}
			if gotLimit != tc.WantLimit {
				t.Fatalf("limit: %d != %d", gotLimit, tc.WantLimit)
			}
		})
	}
}

func Test_validatePubFields(t *testing.T) {
	tcs := []struct {
		Name    string
		Msg     Msg
		WantErr error
	}{
		{
			Name:    "ok",
			Msg:     Msg{Path: NewPath("a/b"), Data: []byte("payload"), Inbox: NewPath("inbox")},
			WantErr: nil,
		},
		{
			Name:    "ok zero inbox",
			Msg:     Msg{Path: NewPath("a/b")},
			WantErr: nil,
		},
		{
			Name:    "empty path",
			Msg:     Msg{},
			WantErr: errEmptyPath,
		},
		{
			Name:    "wild path",
			Msg:     Msg{Path: NewPath("*")},
			WantErr: errWildPath,
		},
		{
			Name:    "wild inbox rejected",
			Msg:     Msg{Path: NewPath("a"), Inbox: NewPath("*")},
			WantErr: errWildInbox,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.Name, func(t *testing.T) {
			err := validatePubFrame(sharedFields{Msg: tc.Msg})
			if !errors.Is(err, tc.WantErr) {
				t.Fatalf("error: %v != %v", err, tc.WantErr)
			}
		})
	}
}

func Test_validateMsg(t *testing.T) {
	tcs := []struct {
		Name    string
		Msg     Msg
		WantErr error
	}{
		{
			Name:    "ok",
			Msg:     Msg{Path: NewPath("a/b"), Data: []byte("payload"), Inbox: NewPath("inbox")},
			WantErr: nil,
		},
		{
			Name:    "wild inbox rejected",
			Msg:     Msg{Path: NewPath("a"), Inbox: NewPath("*")},
			WantErr: errWildInbox,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.Name, func(t *testing.T) {
			err := validateMsg(tc.Msg)
			if !errors.Is(err, tc.WantErr) {
				t.Fatalf("error: %v != %v", err, tc.WantErr)
			}
		})
	}
}

func Test_validateMsgFields(t *testing.T) {
	tcs := []struct {
		Name    string
		Msg     Msg
		WantErr error
	}{
		{
			Name:    "ok",
			Msg:     Msg{Path: NewPath("a/b"), Data: []byte("payload"), Inbox: NewPath("inbox")},
			WantErr: nil,
		},
		{
			Name:    "wild inbox allowed",
			Msg:     Msg{Path: NewPath("a"), Inbox: NewPath("*")},
			WantErr: nil,
		},
		{
			Name:    "empty path",
			Msg:     Msg{},
			WantErr: errEmptyPath,
		},
		{
			Name:    "wild path",
			Msg:     Msg{Path: NewPath("*")},
			WantErr: errWildPath,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.Name, func(t *testing.T) {
			err := validateMsgFrame(sharedFields{Msg: tc.Msg})
			if !errors.Is(err, tc.WantErr) {
				t.Fatalf("error: %v != %v", err, tc.WantErr)
			}
		})
	}
}

func Test_validateSel(t *testing.T) {
	tcs := []struct {
		Name    string
		Sel     Sel
		WantErr error
	}{
		{
			Name:    "ok",
			Sel:     Sel{Path: NewPath("a")},
			WantErr: nil,
		},
		{
			Name:    "ok max limit",
			Sel:     Sel{Path: NewPath("a"), Limit: MaxLimit},
			WantErr: nil,
		},
		{
			Name:    "empty path",
			Sel:     Sel{},
			WantErr: errEmptyPath,
		},
		{
			Name:    "negative limit",
			Sel:     Sel{Path: NewPath("a"), Limit: -1},
			WantErr: errLimitRange,
		},
		{
			Name:    "limit over max",
			Sel:     Sel{Path: NewPath("a"), Limit: MaxLimit + 1},
			WantErr: errLimitRange,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.Name, func(t *testing.T) {
			err := validateSel(tc.Sel)
			if !errors.Is(err, tc.WantErr) {
				t.Fatalf("error: %v != %v", err, tc.WantErr)
			}
		})
	}
}

func Test_parseFields(t *testing.T) {
	t.Run("parses shared fields and compacts msg fields", func(t *testing.T) {
		buf := make([]byte, 0, 96)
		buf = protowire.AppendTag(buf, 99, protowire.VarintType)
		buf = protowire.AppendVarint(buf, 1)
		buf = protowire.AppendTag(buf, numField, protowire.VarintType)
		buf = protowire.AppendVarint(buf, 42)
		buf = protowire.AppendTag(buf, pathField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("a/b"))
		buf = protowire.AppendTag(buf, dataField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("payload"))
		buf = protowire.AppendTag(buf, inboxField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("reply"))
		buf = protowire.AppendTag(buf, 98, protowire.Fixed32Type)
		buf = protowire.AppendFixed32(buf, 3)

		fields, raw, err := parseFields(buf)
		if err != nil {
			t.Fatal(err)
		}

		want := make([]byte, 0, len(raw))
		want = protowire.AppendTag(want, pathField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte("a/b"))
		want = protowire.AppendTag(want, dataField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte("payload"))
		want = protowire.AppendTag(want, inboxField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte("reply"))

		if !bytes.Equal(raw, want) {
			t.Fatalf("compact mismatch: %x != %x", raw, want)
		}
		if len(raw) > 0 && &raw[0] != &buf[0] {
			t.Fatal("raw does not alias body prefix")
		}
		if fields.Num != 42 {
			t.Fatalf("num: %d != %d", fields.Num, 42)
		}
		if got := fields.Msg.Path.String(); got != "a/b" {
			t.Fatalf("path: %q != %q", got, "a/b")
		}
		if !bytes.Equal(fields.Msg.Data, []byte("payload")) {
			t.Fatalf("data: %q != %q", fields.Msg.Data, "payload")
		}
		if got := fields.Msg.Inbox.String(); got != "reply" {
			t.Fatalf("inbox: %q != %q", got, "reply")
		}
	})

	t.Run("repeated fields last wins", func(t *testing.T) {
		buf := make([]byte, 0, 96)
		buf = protowire.AppendTag(buf, numField, protowire.VarintType)
		buf = protowire.AppendVarint(buf, 1)
		buf = protowire.AppendTag(buf, pathField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("a"))
		buf = protowire.AppendTag(buf, dataField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("v1"))
		buf = protowire.AppendTag(buf, numField, protowire.VarintType)
		buf = protowire.AppendVarint(buf, 9)
		buf = protowire.AppendTag(buf, pathField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("b/c"))
		buf = protowire.AppendTag(buf, dataField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("v2"))
		buf = protowire.AppendTag(buf, inboxField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("r"))

		fields, raw, err := parseFields(buf)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) == 0 {
			t.Fatal("empty raw")
		}
		if fields.Num != 9 {
			t.Fatalf("num: %d != %d", fields.Num, 9)
		}
		if got := fields.Msg.Path.String(); got != "b/c" {
			t.Fatalf("path: %q != %q", got, "b/c")
		}
		if !bytes.Equal(fields.Msg.Data, []byte("v2")) {
			t.Fatalf("data: %q != %q", fields.Msg.Data, "v2")
		}
		if got := fields.Msg.Inbox.String(); got != "r" {
			t.Fatalf("inbox: %q != %q", got, "r")
		}
	})

	t.Run("malformed known field keeps accepted prefix and parsed shared fields", func(t *testing.T) {
		buf := make([]byte, 0, 48)
		buf = protowire.AppendTag(buf, numField, protowire.VarintType)
		buf = protowire.AppendVarint(buf, 9)
		buf = protowire.AppendTag(buf, pathField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("path"))
		buf = protowire.AppendTag(buf, dataField, protowire.BytesType)
		buf = protowire.AppendVarint(buf, 5)
		buf = append(buf, 'x')

		fields, raw, err := parseFields(buf)
		if err == nil {
			t.Fatal("no error")
		}

		want := make([]byte, 0, len(raw))
		want = protowire.AppendTag(want, pathField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte("path"))
		if !bytes.Equal(raw, want) {
			t.Fatalf("raw: %x != %x", raw, want)
		}
		if fields.Num != 9 {
			t.Fatalf("num: %d != %d", fields.Num, 9)
		}
		if !fields.Msg.Path.IsZero() || len(fields.Msg.Data) != 0 || !fields.Msg.Inbox.IsZero() {
			t.Fatal("non-zero msg")
		}
	})

	t.Run("invalid path keeps compacted raw and extracted shared fields", func(t *testing.T) {
		buf := make([]byte, 0, 32)
		buf = protowire.AppendTag(buf, numField, protowire.VarintType)
		buf = protowire.AppendVarint(buf, 3)
		buf = protowire.AppendTag(buf, pathField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte{})

		fields, raw, err := parseFields(buf)
		if err == nil {
			t.Fatal("no error")
		}

		want := make([]byte, 0, len(raw))
		want = protowire.AppendTag(want, pathField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte{})
		if !bytes.Equal(raw, want) {
			t.Fatalf("raw: %x != %x", raw, want)
		}
		if fields.Num != 3 {
			t.Fatalf("num: %d != %d", fields.Num, 3)
		}
		if !fields.Msg.Path.IsZero() || len(fields.Msg.Data) != 0 || !fields.Msg.Inbox.IsZero() {
			t.Fatal("non-zero msg")
		}
	})

	t.Run("unknown-only frame", func(t *testing.T) {
		buf := make([]byte, 0, 32)
		buf = protowire.AppendTag(buf, 99, protowire.VarintType)
		buf = protowire.AppendVarint(buf, 7)
		buf = protowire.AppendTag(buf, 98, protowire.Fixed32Type)
		buf = protowire.AppendFixed32(buf, 1)
		buf = protowire.AppendTag(buf, 97, protowire.Fixed64Type)
		buf = protowire.AppendFixed64(buf, 2)
		buf = protowire.AppendTag(buf, 96, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("x"))
		buf = protowire.AppendTag(buf, 95, protowire.StartGroupType)
		buf = protowire.AppendTag(buf, 1, protowire.VarintType)
		buf = protowire.AppendVarint(buf, 1)
		buf = protowire.AppendTag(buf, 95, protowire.EndGroupType)

		fields, raw, err := parseFields(buf)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) != 0 {
			t.Fatalf("len(raw): %d != 0", len(raw))
		}
		if fields.Num != 0 {
			t.Fatalf("num: %d != %d", fields.Num, 0)
		}
		if !fields.Msg.Path.IsZero() || len(fields.Msg.Data) != 0 || !fields.Msg.Inbox.IsZero() {
			t.Fatal("non-zero msg")
		}
	})

	t.Run("empty input", func(t *testing.T) {
		fields, raw, err := parseFields(nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) != 0 {
			t.Fatalf("len(raw): %d != 0", len(raw))
		}
		if fields.Num != 0 {
			t.Fatalf("num: %d != %d", fields.Num, 0)
		}
		if !fields.Msg.Path.IsZero() || len(fields.Msg.Data) != 0 || !fields.Msg.Inbox.IsZero() {
			t.Fatal("non-zero msg")
		}
	})

	t.Run("malformed tag with no accepted fields", func(t *testing.T) {
		fields, raw, err := parseFields([]byte{0x80})
		if err == nil {
			t.Fatal("no error")
		}
		if len(raw) != 0 {
			t.Fatalf("len(raw): %d != 0", len(raw))
		}
		if fields.Num != 0 {
			t.Fatalf("num: %d != %d", fields.Num, 0)
		}
		if !fields.Msg.Path.IsZero() || len(fields.Msg.Data) != 0 || !fields.Msg.Inbox.IsZero() {
			t.Fatal("non-zero msg")
		}
	})

	t.Run("wrong type with no accepted fields", func(t *testing.T) {
		buf := make([]byte, 0, 8)
		buf = protowire.AppendTag(buf, pathField, protowire.VarintType)
		buf = protowire.AppendVarint(buf, 1)

		fields, raw, err := parseFields(buf)
		if err == nil {
			t.Fatal("no error")
		}
		if len(raw) != 0 {
			t.Fatalf("len(raw): %d != 0", len(raw))
		}
		if fields.Num != 0 {
			t.Fatalf("num: %d != %d", fields.Num, 0)
		}
		if !fields.Msg.Path.IsZero() || len(fields.Msg.Data) != 0 || !fields.Msg.Inbox.IsZero() {
			t.Fatal("non-zero msg")
		}
	})

	t.Run("wild path is accepted and keeps compacted raw", func(t *testing.T) {
		buf := make([]byte, 0, 16)
		buf = protowire.AppendTag(buf, pathField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("*"))

		fields, raw, err := parseFields(buf)
		if err != nil {
			t.Fatal(err)
		}
		want := make([]byte, 0, len(raw))
		want = protowire.AppendTag(want, pathField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte("*"))
		if !bytes.Equal(raw, want) {
			t.Fatalf("raw: %x != %x", raw, want)
		}
		if got := fields.Msg.Path.String(); got != "*" {
			t.Fatalf("path: %q != %q", got, "*")
		}
		if len(fields.Msg.Data) != 0 || !fields.Msg.Inbox.IsZero() {
			t.Fatal("unexpected fields")
		}
	})

	t.Run("invalid inbox keeps compacted raw", func(t *testing.T) {
		buf := make([]byte, 0, 24)
		buf = protowire.AppendTag(buf, pathField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("path"))
		buf = protowire.AppendTag(buf, inboxField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte{})

		fields, raw, err := parseFields(buf)
		if err == nil {
			t.Fatal("no error")
		}
		want := make([]byte, 0, len(raw))
		want = protowire.AppendTag(want, pathField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte("path"))
		want = protowire.AppendTag(want, inboxField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte{})
		if !bytes.Equal(raw, want) {
			t.Fatalf("raw: %x != %x", raw, want)
		}
		if got := fields.Msg.Path.String(); got != "path" {
			t.Fatalf("path: %q != %q", got, "path")
		}
		if len(fields.Msg.Data) != 0 || !fields.Msg.Inbox.IsZero() {
			t.Fatal("unexpected fields")
		}
	})

	t.Run("wild inbox is accepted and keeps compacted raw", func(t *testing.T) {
		buf := make([]byte, 0, 24)
		buf = protowire.AppendTag(buf, pathField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("path"))
		buf = protowire.AppendTag(buf, inboxField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("*"))

		fields, raw, err := parseFields(buf)
		if err != nil {
			t.Fatal(err)
		}
		want := make([]byte, 0, len(raw))
		want = protowire.AppendTag(want, pathField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte("path"))
		want = protowire.AppendTag(want, inboxField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte("*"))
		if !bytes.Equal(raw, want) {
			t.Fatalf("raw: %x != %x", raw, want)
		}
		if got := fields.Msg.Path.String(); got != "path" {
			t.Fatalf("path: %q != %q", got, "path")
		}
		if got := fields.Msg.Inbox.String(); got != "*" {
			t.Fatalf("inbox: %q != %q", got, "*")
		}
	})

	t.Run("malformed unknown field with no accepted fields", func(t *testing.T) {
		buf := make([]byte, 0, 16)
		buf = protowire.AppendTag(buf, 99, protowire.BytesType)
		buf = protowire.AppendVarint(buf, 3)
		buf = append(buf, 'x')

		fields, raw, err := parseFields(buf)
		if err == nil {
			t.Fatal("no error")
		}
		if len(raw) != 0 {
			t.Fatalf("len(raw): %d != 0", len(raw))
		}
		if fields.Num != 0 {
			t.Fatalf("num: %d != %d", fields.Num, 0)
		}
		if !fields.Msg.Path.IsZero() || len(fields.Msg.Data) != 0 || !fields.Msg.Inbox.IsZero() {
			t.Fatal("non-zero msg")
		}
	})

	t.Run("num field with wrong type keeps accepted prefix", func(t *testing.T) {
		buf := make([]byte, 0, 24)
		buf = protowire.AppendTag(buf, pathField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("path"))
		buf = protowire.AppendTag(buf, numField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("not-varint"))

		fields, raw, err := parseFields(buf)
		if err == nil {
			t.Fatal("no error")
		}

		want := make([]byte, 0, len(raw))
		want = protowire.AppendTag(want, pathField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte("path"))
		if !bytes.Equal(raw, want) {
			t.Fatalf("raw: %x != %x", raw, want)
		}
		if fields.Num != 0 {
			t.Fatalf("num: %d != %d", fields.Num, 0)
		}
		if !fields.Msg.Path.IsZero() || len(fields.Msg.Data) != 0 || !fields.Msg.Inbox.IsZero() {
			t.Fatal("non-zero msg")
		}
	})

	t.Run("malformed num varint keeps accepted prefix", func(t *testing.T) {
		buf := make([]byte, 0, 24)
		buf = protowire.AppendTag(buf, pathField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("path"))
		buf = protowire.AppendTag(buf, numField, protowire.VarintType)
		buf = append(buf, 0x80) // truncated varint

		fields, raw, err := parseFields(buf)
		if err == nil {
			t.Fatal("no error")
		}

		want := make([]byte, 0, len(raw))
		want = protowire.AppendTag(want, pathField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte("path"))
		if !bytes.Equal(raw, want) {
			t.Fatalf("raw: %x != %x", raw, want)
		}
		if fields.Num != 0 {
			t.Fatalf("num: %d != %d", fields.Num, 0)
		}
		if !fields.Msg.Path.IsZero() || len(fields.Msg.Data) != 0 || !fields.Msg.Inbox.IsZero() {
			t.Fatal("non-zero msg")
		}
	})

	t.Run("malformed trailing tag keeps compacted prefix and shared fields", func(t *testing.T) {
		buf := make([]byte, 0, 48)
		buf = protowire.AppendTag(buf, numField, protowire.VarintType)
		buf = protowire.AppendVarint(buf, 11)
		buf = protowire.AppendTag(buf, pathField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("path"))
		buf = append(buf, 0x80)

		fields, raw, err := parseFields(buf)
		if err == nil {
			t.Fatal("no error")
		}
		want := make([]byte, 0, len(raw))
		want = protowire.AppendTag(want, pathField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte("path"))
		if !bytes.Equal(raw, want) {
			t.Fatalf("raw: %x != %x", raw, want)
		}
		if fields.Num != 11 {
			t.Fatalf("num: %d != %d", fields.Num, 11)
		}
		if !fields.Msg.Path.IsZero() || len(fields.Msg.Data) != 0 || !fields.Msg.Inbox.IsZero() {
			t.Fatal("non-zero msg")
		}
	})

	t.Run("malformed unknown fixed32 returns parse error", func(t *testing.T) {
		buf := make([]byte, 0, 8)
		buf = protowire.AppendTag(buf, 99, protowire.Fixed32Type)
		buf = append(buf, 0x01, 0x02, 0x03) // truncated fixed32

		fields, raw, err := parseFields(buf)
		if err == nil {
			t.Fatal("no error")
		}
		if len(raw) != 0 {
			t.Fatalf("len(raw): %d != 0", len(raw))
		}
		if fields.Num != 0 {
			t.Fatalf("num: %d != %d", fields.Num, 0)
		}
		if !fields.Msg.Path.IsZero() || len(fields.Msg.Data) != 0 || !fields.Msg.Inbox.IsZero() {
			t.Fatal("non-zero msg")
		}
	})

	t.Run("msg field data aliases compacted raw", func(t *testing.T) {
		buf := make([]byte, 0, 16)
		buf = protowire.AppendTag(buf, dataField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("a"))

		fields, raw, err := parseFields(buf)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) == 0 {
			t.Fatal("empty raw")
		}
		if len(fields.Msg.Data) != 1 || fields.Msg.Data[0] != 'a' {
			t.Fatalf("data: %q != %q", fields.Msg.Data, "a")
		}

		raw[len(raw)-1] = 'z'
		if len(fields.Msg.Data) != 1 || fields.Msg.Data[0] != 'z' {
			t.Fatalf("data did not alias raw: %q", fields.Msg.Data)
		}
	})
}

func Test_parsePubFrame(t *testing.T) {
	t.Run("parses and compacts known fields", func(t *testing.T) {
		buf := make([]byte, 0, 64)
		buf = protowire.AppendTag(buf, 99, protowire.VarintType)
		buf = protowire.AppendVarint(buf, 1)
		buf = protowire.AppendTag(buf, pathField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("a/b"))
		buf = protowire.AppendTag(buf, 98, protowire.Fixed32Type)
		buf = protowire.AppendFixed32(buf, 7)
		buf = protowire.AppendTag(buf, dataField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("payload"))
		buf = protowire.AppendTag(buf, inboxField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("inbox"))
		buf = protowire.AppendTag(buf, 97, protowire.VarintType)
		buf = protowire.AppendVarint(buf, 2)

		fields, raw, err := parseFields(buf)
		msg := fields.Msg
		if err != nil {
			t.Fatal(err)
		}

		want := make([]byte, 0, len(raw))
		want = protowire.AppendTag(want, pathField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte("a/b"))
		want = protowire.AppendTag(want, dataField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte("payload"))
		want = protowire.AppendTag(want, inboxField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte("inbox"))

		if !bytes.Equal(raw, want) {
			t.Fatalf("compact mismatch: %x != %x", raw, want)
		}
		if len(raw) > 0 && &raw[0] != &buf[0] {
			t.Fatal("raw does not alias body prefix")
		}
		if got := msg.Path.String(); got != "a/b" {
			t.Fatalf("path: %q != %q", got, "a/b")
		}
		if !bytes.Equal(msg.Data, []byte("payload")) {
			t.Fatalf("data: %q != %q", msg.Data, "payload")
		}
		if got := msg.Inbox.String(); got != "inbox" {
			t.Fatalf("inbox: %q != %q", got, "inbox")
		}
	})

	t.Run("extracts num and omits it from compacted raw", func(t *testing.T) {
		buf := make([]byte, 0, 64)
		buf = protowire.AppendTag(buf, numField, protowire.VarintType)
		buf = protowire.AppendVarint(buf, 42)
		buf = protowire.AppendTag(buf, pathField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("a/b"))
		buf = protowire.AppendTag(buf, dataField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("payload"))

		fields, raw, err := parseFields(buf)
		num, msg := fields.Num, fields.Msg
		if err != nil {
			t.Fatal(err)
		}
		if num != 42 {
			t.Fatalf("num: %d != %d", num, 42)
		}

		want := make([]byte, 0, len(raw))
		want = protowire.AppendTag(want, pathField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte("a/b"))
		want = protowire.AppendTag(want, dataField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte("payload"))
		if !bytes.Equal(raw, want) {
			t.Fatalf("compact mismatch: %x != %x", raw, want)
		}
		if got := msg.Path.String(); got != "a/b" {
			t.Fatalf("path: %q != %q", got, "a/b")
		}
		if !bytes.Equal(msg.Data, []byte("payload")) {
			t.Fatalf("data: %q != %q", msg.Data, "payload")
		}
	})

	t.Run("repeated fields last wins", func(t *testing.T) {
		buf := make([]byte, 0, 64)
		buf = protowire.AppendTag(buf, pathField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("a"))
		buf = protowire.AppendTag(buf, dataField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("v1"))
		buf = protowire.AppendTag(buf, pathField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("b/c"))
		buf = protowire.AppendTag(buf, dataField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("v2"))
		buf = protowire.AppendTag(buf, inboxField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("r"))

		fields, raw, err := parseFields(buf)
		msg := fields.Msg
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) == 0 {
			t.Fatal("empty raw")
		}
		if got := msg.Path.String(); got != "b/c" {
			t.Fatalf("path: %q != %q", got, "b/c")
		}
		if !bytes.Equal(msg.Data, []byte("v2")) {
			t.Fatalf("data: %q != %q", msg.Data, "v2")
		}
		if got := msg.Inbox.String(); got != "r" {
			t.Fatalf("inbox: %q != %q", got, "r")
		}
	})

	t.Run("unknown-only frame", func(t *testing.T) {
		buf := make([]byte, 0, 16)
		buf = protowire.AppendTag(buf, 99, protowire.VarintType)
		buf = protowire.AppendVarint(buf, 7)
		buf = protowire.AppendTag(buf, 98, protowire.Fixed32Type)
		buf = protowire.AppendFixed32(buf, 1)

		fields, raw, err := parseFields(buf)
		msg := fields.Msg
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) != 0 {
			t.Fatalf("len: %d != 0", len(raw))
		}
		if !msg.Path.IsZero() || len(msg.Data) != 0 || !msg.Inbox.IsZero() {
			t.Fatal("non-zero msg")
		}
	})

	t.Run("malformed tag with no accepted fields", func(t *testing.T) {
		buf := []byte{0x80}

		fields, raw, err := parseFields(buf)
		msg := fields.Msg
		if err == nil {
			t.Fatal("no error")
		}
		if len(raw) != 0 {
			t.Fatalf("len: %d != 0", len(raw))
		}
		if !msg.Path.IsZero() || len(msg.Data) != 0 || !msg.Inbox.IsZero() {
			t.Fatal("non-zero msg")
		}
	})

	t.Run("wrong type with no accepted fields", func(t *testing.T) {
		buf := make([]byte, 0, 8)
		buf = protowire.AppendTag(buf, pathField, protowire.VarintType)
		buf = protowire.AppendVarint(buf, 1)

		fields, raw, err := parseFields(buf)
		msg := fields.Msg
		if err == nil {
			t.Fatal("no error")
		}
		if len(raw) != 0 {
			t.Fatalf("len: %d != 0", len(raw))
		}
		if !msg.Path.IsZero() || len(msg.Data) != 0 || !msg.Inbox.IsZero() {
			t.Fatal("non-zero msg")
		}
	})

	t.Run("malformed known field keeps accepted prefix", func(t *testing.T) {
		buf := make([]byte, 0, 16)
		buf = protowire.AppendTag(buf, pathField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("path"))
		buf = protowire.AppendTag(buf, dataField, protowire.BytesType)
		buf = protowire.AppendVarint(buf, 5)
		buf = append(buf, 'x')

		fields, raw, err := parseFields(buf)
		msg := fields.Msg
		if err == nil {
			t.Fatal("no error")
		}
		want := make([]byte, 0, len(raw))
		want = protowire.AppendTag(want, pathField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte("path"))
		if !bytes.Equal(raw, want) {
			t.Fatalf("raw: %x != %x", raw, want)
		}
		if !msg.Path.IsZero() || len(msg.Data) != 0 || !msg.Inbox.IsZero() {
			t.Fatal("non-zero msg")
		}
	})

	t.Run("invalid path keeps compacted raw", func(t *testing.T) {
		buf := make([]byte, 0, 16)
		buf = protowire.AppendTag(buf, pathField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte{})

		fields, raw, err := parseFields(buf)
		msg := fields.Msg
		if err == nil {
			t.Fatal("no error")
		}
		want := make([]byte, 0, len(raw))
		want = protowire.AppendTag(want, pathField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte{})
		if !bytes.Equal(raw, want) {
			t.Fatalf("raw: %x != %x", raw, want)
		}
		if !msg.Path.IsZero() || len(msg.Data) != 0 || !msg.Inbox.IsZero() {
			t.Fatal("non-zero msg")
		}
	})

	t.Run("wild path is accepted and keeps compacted raw", func(t *testing.T) {
		buf := make([]byte, 0, 16)
		buf = protowire.AppendTag(buf, pathField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("*"))

		fields, raw, err := parseFields(buf)
		msg := fields.Msg
		if err != nil {
			t.Fatal(err)
		}
		want := make([]byte, 0, len(raw))
		want = protowire.AppendTag(want, pathField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte("*"))
		if !bytes.Equal(raw, want) {
			t.Fatalf("raw: %x != %x", raw, want)
		}
		if got := msg.Path.String(); got != "*" {
			t.Fatalf("path: %q != %q", got, "*")
		}
		if len(msg.Data) != 0 || !msg.Inbox.IsZero() {
			t.Fatal("unexpected fields")
		}
	})

	t.Run("invalid inbox keeps compacted raw", func(t *testing.T) {
		buf := make([]byte, 0, 24)
		buf = protowire.AppendTag(buf, pathField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("path"))
		buf = protowire.AppendTag(buf, inboxField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte{})

		fields, raw, err := parseFields(buf)
		msg := fields.Msg
		if err == nil {
			t.Fatal("no error")
		}
		want := make([]byte, 0, len(raw))
		want = protowire.AppendTag(want, pathField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte("path"))
		want = protowire.AppendTag(want, inboxField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte{})
		if !bytes.Equal(raw, want) {
			t.Fatalf("raw: %x != %x", raw, want)
		}
		if got := msg.Path.String(); got != "path" {
			t.Fatalf("path: %q != %q", got, "path")
		}
	})

	t.Run("wild inbox is accepted and keeps compacted raw", func(t *testing.T) {
		buf := make([]byte, 0, 24)
		buf = protowire.AppendTag(buf, pathField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("path"))
		buf = protowire.AppendTag(buf, inboxField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("*"))

		fields, raw, err := parseFields(buf)
		msg := fields.Msg
		if err != nil {
			t.Fatal(err)
		}
		want := make([]byte, 0, len(raw))
		want = protowire.AppendTag(want, pathField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte("path"))
		want = protowire.AppendTag(want, inboxField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte("*"))
		if !bytes.Equal(raw, want) {
			t.Fatalf("raw: %x != %x", raw, want)
		}
		if got := msg.Path.String(); got != "path" {
			t.Fatalf("path: %q != %q", got, "path")
		}
		if got := msg.Inbox.String(); got != "*" {
			t.Fatalf("inbox: %q != %q", got, "*")
		}
	})

	t.Run("malformed unknown field with no accepted fields", func(t *testing.T) {
		buf := make([]byte, 0, 16)
		buf = protowire.AppendTag(buf, 99, protowire.BytesType)
		buf = protowire.AppendVarint(buf, 3)
		buf = append(buf, 'x')

		fields, raw, err := parseFields(buf)
		msg := fields.Msg
		if err == nil {
			t.Fatal("no error")
		}
		if len(raw) != 0 {
			t.Fatalf("len: %d != 0", len(raw))
		}
		if !msg.Path.IsZero() || len(msg.Data) != 0 || !msg.Inbox.IsZero() {
			t.Fatal("non-zero msg")
		}
	})

	t.Run("num field with wrong type keeps accepted prefix", func(t *testing.T) {
		buf := make([]byte, 0, 24)
		buf = protowire.AppendTag(buf, pathField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("path"))
		buf = protowire.AppendTag(buf, numField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("not-varint"))

		fields, raw, err := parseFields(buf)
		msg := fields.Msg
		if err == nil {
			t.Fatal("no error")
		}

		want := make([]byte, 0, len(raw))
		want = protowire.AppendTag(want, pathField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte("path"))
		if !bytes.Equal(raw, want) {
			t.Fatalf("raw: %x != %x", raw, want)
		}
		if !msg.Path.IsZero() || len(msg.Data) != 0 || !msg.Inbox.IsZero() {
			t.Fatal("non-zero msg")
		}
	})

	t.Run("malformed num varint keeps accepted prefix", func(t *testing.T) {
		buf := make([]byte, 0, 24)
		buf = protowire.AppendTag(buf, pathField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("path"))
		buf = protowire.AppendTag(buf, numField, protowire.VarintType)
		buf = append(buf, 0x80) // truncated varint

		fields, raw, err := parseFields(buf)
		msg := fields.Msg
		if err == nil {
			t.Fatal("no error")
		}

		want := make([]byte, 0, len(raw))
		want = protowire.AppendTag(want, pathField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte("path"))
		if !bytes.Equal(raw, want) {
			t.Fatalf("raw: %x != %x", raw, want)
		}
		if !msg.Path.IsZero() || len(msg.Data) != 0 || !msg.Inbox.IsZero() {
			t.Fatal("non-zero msg")
		}
	})
}

func TestRouter_internalNoopBranches(t *testing.T) {
	t.Run("update with nil old and new is a no-op", func(t *testing.T) {
		rr := NewRouter()
		rr.update()
	})

	t.Run("match on zero path returns no entries", func(t *testing.T) {
		var tree rnode
		if got := tree.Match(Path{}); len(got) != 0 {
			t.Fatalf("len(entries): %d != 0", len(got))
		}
	})

	t.Run("leaf lookup without createMissing returns nil", func(t *testing.T) {
		var tree rnode
		if got := tree.leaf(NewPath("a/b"), false); got != nil {
			t.Fatal("expected nil")
		}
	})
}

func TestRouter_Subscribe_limitRange(t *testing.T) {
	rr := NewRouter()

	if _, err := rr.Subscribe(Sel{Path: NewPath("a"), Limit: -1}, func(Msg) {}); !errors.Is(err, errLimitRange) {
		t.Fatalf("negative limit: %v", err)
	}
	if _, err := rr.Subscribe(Sel{Path: NewPath("a"), Limit: MaxLimit + 1}, func(Msg) {}); !errors.Is(err, errLimitRange) {
		t.Fatalf("limit over max: %v", err)
	}
}

func TestRouter_Subscribe_done(t *testing.T) {
	t.Run("done closes on cancel", func(t *testing.T) {
		rr := NewRouter()
		sub, err := rr.Subscribe(Sel{Path: NewPath("a")}, func(Msg) {})
		if err != nil {
			t.Fatal(err)
		}

		select {
		case <-sub.Done():
			t.Fatal("done closed early")
		default:
		}

		sub.Cancel()

		select {
		case <-sub.Done():
		default:
			t.Fatal("done not closed")
		}
	})

	t.Run("done closes when limit is reached", func(t *testing.T) {
		rr := NewRouter()
		sub, err := rr.Subscribe(Sel{Path: NewPath("a"), Limit: 1}, func(Msg) {})
		if err != nil {
			t.Fatal(err)
		}

		if err := rr.Publish(Msg{Path: NewPath("a"), Data: []byte("x")}); err != nil {
			t.Fatal(err)
		}

		select {
		case <-sub.Done():
		default:
			t.Fatal("done not closed")
		}
	})
}

func TestRouter_deliver_limit(t *testing.T) {
	t.Run("limited entry is removed after limit deliveries", func(t *testing.T) {
		rr := NewRouter()
		var delivered int
		e := &rent{
			Sel: Sel{Path: NewPath("a"), Limit: 2},
			Do: func(Msg, []byte) {
				delivered++
			},
			doneC: make(chan struct{}),
			unsub: func() {},
		}
		rr.update(rop{ropIns, e})

		msg := Msg{Path: NewPath("a"), Data: []byte("x")}
		for range 3 {
			ee := rr.route(msg.Path)
			rr.deliver(ee, msg, nil)
		}

		if delivered != 2 {
			t.Fatalf("delivered: %d != %d", delivered, 2)
		}
		if got := len(rr.route(msg.Path)); got != 0 {
			t.Fatalf("len(route): %d != 0", got)
		}
	})

	t.Run("unlimited entry keeps receiving deliveries", func(t *testing.T) {
		rr := NewRouter()
		var delivered int
		e := &rent{
			Sel: Sel{Path: NewPath("a")},
			Do: func(Msg, []byte) {
				delivered++
			},
			doneC: make(chan struct{}),
		}
		rr.update(rop{ropIns, e})

		msg := Msg{Path: NewPath("a"), Data: []byte("x")}
		for range 3 {
			ee := rr.route(msg.Path)
			rr.deliver(ee, msg, nil)
		}

		if delivered != 3 {
			t.Fatalf("delivered: %d != %d", delivered, 3)
		}
		if got := len(rr.route(msg.Path)); got != 1 {
			t.Fatalf("len(route): %d != 1", got)
		}
	})
}

func mustNewServerForTest(t *testing.T) *Server {
	t.Helper()

	s, err := NewServer(NewRouter(), ServerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestServer_NewServer(t *testing.T) {
	_, err := NewServer(nil, ServerConfig{})
	if err == nil {
		t.Fatal("no error")
	}
}

func TestServer_readFrames(t *testing.T) {
	t.Run("short frame", func(t *testing.T) {
		s := mustNewServerForTest(t)
		sc := newBareServerConn(newTestConnWithBytes([]byte{3, 0, 0, subFrameType}))

		err := s.readFrames(context.Background(), discardLogger, sc)
		if !errors.Is(err, errShortFrame) {
			t.Fatal(err)
		}
	})

	t.Run("unknown frame discard fails on short body", func(t *testing.T) {
		s := mustNewServerForTest(t)
		unknown := newUnknownFrame(99, []byte{1, 2})
		unknown = unknown[:len(unknown)-1]
		sc := newBareServerConn(newTestConnWithBytes(unknown))

		err := s.readFrames(context.Background(), discardLogger, sc)
		if !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
	})

	t.Run("unknown frame is discarded, pub frame is handled", func(t *testing.T) {
		s := mustNewServerForTest(t)
		msgC := make(chan Msg, 1)
		sub, err := s.router.Subscribe(Sel{Path: NewPath("a")}, func(m Msg) {
			msgC <- m
		})
		if err != nil {
			t.Fatal(err)
		}
		defer sub.Cancel()

		pub := appendFrame(nil, pubFrameType, func(b []byte) []byte {
			return appendMsgFields(b, Msg{
				Path:  NewPath("a"),
				Data:  []byte("hi"),
				Inbox: NewPath("inbox"),
			})
		})

		wire := appendFrames(newUnknownFrame(99, []byte{1, 2, 3}), pub)
		sc := newBareServerConn(newTestConnWithBytes(wire))

		err = s.readFrames(context.Background(), discardLogger, sc)
		if !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}

		got := <-msgC
		if got.Path.String() != "a" {
			t.Fatalf("path: %q != %q", got.Path.String(), "a")
		}
		if !bytes.Equal(got.Data, []byte("hi")) {
			t.Fatalf("data: %q != %q", got.Data, "hi")
		}
		if got.Inbox.String() != "inbox" {
			t.Fatalf("inbox: %q != %q", got.Inbox.String(), "inbox")
		}
	})

	t.Run("known frame with short body fails read", func(t *testing.T) {
		s := mustNewServerForTest(t)
		wire := newSubFrame(1, NewPath("path"))
		wire = wire[:len(wire)-1]
		sc := newBareServerConn(newTestConnWithBytes(wire))

		err := s.readFrames(context.Background(), discardLogger, sc)
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatal(err)
		}
	})

	t.Run("handler error is returned", func(t *testing.T) {
		s := mustNewServerForTest(t)
		wire := appendFrame(nil, pubFrameType, func(b []byte) []byte { return b })
		sc := newBareServerConn(newTestConnWithBytes(wire))

		err := s.readFrames(context.Background(), discardLogger, sc)
		if !errors.Is(err, errEmptyPath) {
			t.Fatal(err)
		}
	})

	t.Run("duplicate sub error is returned", func(t *testing.T) {
		s := mustNewServerForTest(t)
		wire := appendFrames(
			newSubFrame(1, NewPath("a")),
			newSubFrame(1, NewPath("b")),
		)
		sc := newBareServerConn(newTestConnWithBytes(wire))

		err := s.readFrames(context.Background(), discardLogger, sc)
		if !errors.Is(err, errDuplicateSub) {
			t.Fatal(err)
		}
	})

}

func TestServer_handlePub(t *testing.T) {
	t.Run("parse failure", func(t *testing.T) {
		s := mustNewServerForTest(t)
		err := s.handlePub(context.Background(), discardLogger, newBareServerConn(&testConn{}), []byte{0x80})
		if err == nil {
			t.Fatal("no error")
		}
	})

	t.Run("delivers to routed subscribers", func(t *testing.T) {
		s := mustNewServerForTest(t)
		msgC := make(chan Msg, 1)
		sub, err := s.router.Subscribe(Sel{Path: NewPath("a")}, func(m Msg) {
			msgC <- m
		})
		if err != nil {
			t.Fatal(err)
		}
		defer sub.Cancel()

		body := appendMsgFields(nil, Msg{
			Path:  NewPath("a"),
			Data:  []byte("hi"),
			Inbox: NewPath("inbox"),
		})
		if err := s.handlePub(context.Background(), discardLogger, newBareServerConn(&testConn{}), body); err != nil {
			t.Fatal(err)
		}

		got := <-msgC
		if got.Path.String() != "a" {
			t.Fatalf("path: %q != %q", got.Path.String(), "a")
		}
		if !bytes.Equal(got.Data, []byte("hi")) {
			t.Fatalf("data: %q != %q", got.Data, "hi")
		}
		if got.Inbox.String() != "inbox" {
			t.Fatalf("inbox: %q != %q", got.Inbox.String(), "inbox")
		}
	})

	t.Run("denied inbox drops publish", func(t *testing.T) {
		s := mustNewServerForTest(t)
		msgC := make(chan Msg, 1)
		sub, err := s.router.Subscribe(Sel{Path: NewPath("a")}, func(m Msg) {
			msgC <- m
		})
		if err != nil {
			t.Fatal(err)
		}
		defer sub.Cancel()

		sc := newBareServerConn(&testConn{})
		sc.allow = func(p Path, a Action) bool {
			return a == ActionPub && p.Equal(NewPath("a"))
		}

		body := appendMsgFields(nil, Msg{
			Path:  NewPath("a"),
			Data:  []byte("hi"),
			Inbox: NewPath("inbox"),
		})
		if err := s.handlePub(context.Background(), discardLogger, sc, body); err != nil {
			t.Fatal(err)
		}

		select {
		case got := <-msgC:
			t.Fatalf("unexpected message: %+v", got)
		default:
		}
	})

}

func TestServer_handleSub(t *testing.T) {
	t.Run("bad proto", func(t *testing.T) {
		s := mustNewServerForTest(t)
		sc := newBareServerConn(&testConn{})
		err := s.handleSub(context.Background(), discardLogger, sc, []byte{0xff})
		if err == nil {
			t.Fatal("no error")
		}
	})

	t.Run("bad path", func(t *testing.T) {
		s := mustNewServerForTest(t)
		sc := newBareServerConn(&testConn{})
		err := s.handleSub(context.Background(), discardLogger, sc, newSubFrame(1, Path{})[frameHdrLen:])
		if err == nil {
			t.Fatal("no error")
		}
	})

	t.Run("duplicate sub number fails and keeps existing sub", func(t *testing.T) {
		s := mustNewServerForTest(t)
		sc := newBareServerConn(&testConn{})

		if err := s.handleSub(context.Background(), discardLogger, sc, newSubFrame(1, NewPath("a"))[frameHdrLen:]); err != nil {
			t.Fatal(err)
		}
		if err := s.handleSub(context.Background(), discardLogger, sc, newSubFrame(1, NewPath("b"))[frameHdrLen:]); !errors.Is(err, errDuplicateSub) {
			t.Fatal(err)
		}

		if got := len(sc.subs); got != 1 {
			t.Fatalf("len(subs): %d != 1", got)
		}
		if got := sc.subs[1].Sel.Path.String(); got != "a" {
			t.Fatalf("path: %q != %q", got, "a")
		}
	})

	t.Run("denied sub is ignored", func(t *testing.T) {
		s := mustNewServerForTest(t)
		sc := newBareServerConn(&testConn{})
		sc.allow = func(Path, Action) bool { return false }

		if err := s.handleSub(context.Background(), discardLogger, sc, newSubFrame(1, NewPath("b"))[frameHdrLen:]); err != nil {
			t.Fatal(err)
		}
		if len(sc.subs) != 0 {
			t.Fatalf("len(subs): %d != 0", len(sc.subs))
		}
	})

	t.Run("long group is rejected", func(t *testing.T) {
		s := mustNewServerForTest(t)
		sc := newBareServerConn(&testConn{})

		body := appendFrame(nil, subFrameType, func(b []byte) []byte {
			b = protowire.AppendTag(b, numField, protowire.VarintType)
			b = protowire.AppendVarint(b, 1)
			b = protowire.AppendTag(b, pathField, protowire.BytesType)
			b = protowire.AppendBytes(b, NewPath("path").p)
			b = protowire.AppendTag(b, 3, protowire.BytesType)
			b = protowire.AppendBytes(b, []byte(strings.Repeat("x", MaxGroupLen+1)))
			return b
		})[frameHdrLen:]

		err := s.handleSub(context.Background(), discardLogger, sc, body)
		if !errors.Is(err, errLongGroup) {
			t.Fatal(err)
		}
	})

	t.Run("limit is stored on subscription", func(t *testing.T) {
		s := mustNewServerForTest(t)
		sc := newBareServerConn(&testConn{})

		body := newSubFrameSel(1, Sel{Path: NewPath("path"), Limit: 5})[frameHdrLen:]
		if err := s.handleSub(context.Background(), discardLogger, sc, body); err != nil {
			t.Fatal(err)
		}
		if got := sc.subs[1].Sel.Limit; got != 5 {
			t.Fatalf("limit: %d != %d", got, 5)
		}
	})

	t.Run("negative limit is clamped to zero", func(t *testing.T) {
		s := mustNewServerForTest(t)
		sc := newBareServerConn(&testConn{})

		wireLimit := int64(-7)
		body := appendFrame(nil, subFrameType, func(b []byte) []byte {
			b = protowire.AppendTag(b, numField, protowire.VarintType)
			b = protowire.AppendVarint(b, 1)
			b = protowire.AppendTag(b, pathField, protowire.BytesType)
			b = protowire.AppendBytes(b, []byte("path"))
			b = protowire.AppendTag(b, 4, protowire.VarintType)
			b = protowire.AppendVarint(b, uint64(wireLimit))
			return b
		})[frameHdrLen:]

		if err := s.handleSub(context.Background(), discardLogger, sc, body); err != nil {
			t.Fatal(err)
		}
		if got := sc.subs[1].Sel.Limit; got != 0 {
			t.Fatalf("limit: %d != 0", got)
		}
	})

	t.Run("over max limit is clamped", func(t *testing.T) {
		s := mustNewServerForTest(t)
		sc := newBareServerConn(&testConn{})

		body := appendFrame(nil, subFrameType, func(b []byte) []byte {
			b = protowire.AppendTag(b, numField, protowire.VarintType)
			b = protowire.AppendVarint(b, 1)
			b = protowire.AppendTag(b, pathField, protowire.BytesType)
			b = protowire.AppendBytes(b, []byte("path"))
			b = protowire.AppendTag(b, 4, protowire.VarintType)
			b = protowire.AppendVarint(b, uint64(MaxLimit+10))
			return b
		})[frameHdrLen:]

		if err := s.handleSub(context.Background(), discardLogger, sc, body); err != nil {
			t.Fatal(err)
		}
		if got := sc.subs[1].Sel.Limit; got != MaxLimit {
			t.Fatalf("limit: %d != %d", got, MaxLimit)
		}
	})

	t.Run("limit auto-unsub removes server sub", func(t *testing.T) {
		s := mustNewServerForTest(t)
		sc := newBareServerConn(&testConn{})

		body := newSubFrameSel(1, Sel{Path: NewPath("path"), Limit: 1})[frameHdrLen:]
		if err := s.handleSub(context.Background(), discardLogger, sc, body); err != nil {
			t.Fatal(err)
		}
		if got := len(sc.subs); got != 1 {
			t.Fatalf("len(subs): %d != 1", got)
		}

		if err := s.router.Publish(Msg{Path: NewPath("path"), Data: []byte("one")}); err != nil {
			t.Fatal(err)
		}
		if got := len(sc.subs); got != 0 {
			t.Fatalf("len(subs): %d != 0", got)
		}

		sc.mu.Lock()
		n := len(sc.wbufs)
		sc.mu.Unlock()
		if n != 2 {
			t.Fatalf("buffers after first publish: %d != 2", n)
		}

		if err := s.router.Publish(Msg{Path: NewPath("path"), Data: []byte("two")}); err != nil {
			t.Fatal(err)
		}

		sc.mu.Lock()
		n2 := len(sc.wbufs)
		sc.mu.Unlock()
		if n2 != n {
			t.Fatalf("buffers after second publish: %d != %d", n2, n)
		}
	})

	t.Run("duplicate sub does not replace existing", func(t *testing.T) {
		s := mustNewServerForTest(t)
		sc := newBareServerConn(&testConn{})

		first := newSubFrameSel(1, Sel{Path: NewPath("path"), Limit: 1})[frameHdrLen:]
		if err := s.handleSub(context.Background(), discardLogger, sc, first); err != nil {
			t.Fatal(err)
		}

		old := sc.subs[1]

		second := newSubFrameSel(1, Sel{Path: NewPath("path"), Group: NewGroup("workers")})[frameHdrLen:]
		if err := s.handleSub(context.Background(), discardLogger, sc, second); !errors.Is(err, errDuplicateSub) {
			t.Fatal(err)
		}

		if got := sc.subs[1]; got != old {
			t.Fatal("existing sub was replaced")
		}
	})
}

func TestServer_handleUnsub(t *testing.T) {
	t.Run("bad proto", func(t *testing.T) {
		s := mustNewServerForTest(t)
		sc := newBareServerConn(&testConn{})
		err := s.handleUnsub(context.Background(), discardLogger, sc, []byte{0xff})
		if err == nil {
			t.Fatal("no error")
		}
	})

	t.Run("missing sub is a no-op", func(t *testing.T) {
		s := mustNewServerForTest(t)
		sc := newBareServerConn(&testConn{})
		if err := s.handleUnsub(context.Background(), discardLogger, sc, newUnsubFrame(1)[frameHdrLen:]); err != nil {
			t.Fatal(err)
		}
		if len(sc.subs) != 0 {
			t.Fatalf("len(subs): %d != 0", len(sc.subs))
		}
	})

	t.Run("existing sub is removed", func(t *testing.T) {
		s := mustNewServerForTest(t)
		sc := newBareServerConn(&testConn{})

		if err := s.handleSub(context.Background(), discardLogger, sc, newSubFrame(1, NewPath("path"))[frameHdrLen:]); err != nil {
			t.Fatal(err)
		}
		if err := s.handleUnsub(context.Background(), discardLogger, sc, newUnsubFrame(1)[frameHdrLen:]); err != nil {
			t.Fatal(err)
		}
		if len(sc.subs) != 0 {
			t.Fatalf("len(subs): %d != 0", len(sc.subs))
		}

		sc.mu.Lock()
		sc.wbufs = nil
		sc.mu.Unlock()
		if err := s.router.Publish(Msg{Path: NewPath("path"), Data: []byte("gone")}); err != nil {
			t.Fatal(err)
		}
		sc.mu.Lock()
		n := len(sc.wbufs)
		sc.mu.Unlock()
		if n != 0 {
			t.Fatalf("unsub delivered %d buffers", n)
		}
	})

}

func TestServer_writeFrames(t *testing.T) {
	t.Run("write failure", func(t *testing.T) {
		s := mustNewServerForTest(t)
		sc := newBareServerConn(&testConn{writeErr: errors.New("write failed")})
		sc.wbufs = net.Buffers{[]byte("payload")}
		fillServerSignal(sc)

		err := s.writeFrames(context.Background(), discardLogger, sc)
		if err == nil {
			t.Fatal("no error")
		}
		tc := sc.Conn.(*testConn)
		if !tc.closed.Load() {
			t.Fatal("expected close")
		}
	})

	t.Run("context canceled still flushes current buffers", func(t *testing.T) {
		s := mustNewServerForTest(t)
		tc := &testConn{}
		sc := newBareServerConn(tc)
		sc.wbufs = net.Buffers{[]byte("payload")}

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := s.writeFrames(ctx, discardLogger, sc)
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		if !bytes.Equal(tc.wrote(), []byte("payload")) {
			t.Fatalf("wrote: %q != %q", tc.wrote(), []byte("payload"))
		}
		if !tc.closed.Load() {
			t.Fatal("expected close")
		}
	})
}

func TestServer_keepalive(t *testing.T) {
	t.Run("injects keepalive when writer is idle", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s := mustNewServerForTest(t)
			sc := newBareServerConn(&testConn{})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			errC := make(chan error, 1)
			go func() {
				errC <- s.keepalive(ctx, discardLogger, sc)
			}()

			synctest.Wait()
			time.Sleep(1 * time.Second)
			synctest.Wait()

			sc.mu.Lock()
			if len(sc.wbufs) != 1 || !bytes.Equal(sc.wbufs[0], []byte{4, 0, 0, 0}) {
				t.Fatalf("wbufs: %v", sc.wbufs)
			}
			sc.mu.Unlock()
			if len(sc.wbufC) != 1 {
				t.Fatalf("len(wbufC): %d != 1", len(sc.wbufC))
			}

			cancel()
			if err := <-errC; !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		})
	})

	t.Run("does not inject keepalive while outbound buffer is non-empty", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s := mustNewServerForTest(t)
			sc := newBareServerConn(&testConn{})
			sc.wbufs = net.Buffers{[]byte("pending")}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			errC := make(chan error, 1)
			go func() {
				errC <- s.keepalive(ctx, discardLogger, sc)
			}()

			synctest.Wait()
			time.Sleep(1 * time.Second)
			synctest.Wait()

			sc.mu.Lock()
			if len(sc.wbufs) != 1 || !bytes.Equal(sc.wbufs[0], []byte("pending")) {
				t.Fatalf("wbufs: %v", sc.wbufs)
			}
			sc.mu.Unlock()
			if len(sc.wbufC) != 0 {
				t.Fatalf("len(wbufC): %d != 0", len(sc.wbufC))
			}

			cancel()
			if err := <-errC; !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		})
	})

	t.Run("signal send is dropped when channel is already full", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s := mustNewServerForTest(t)
			sc := newBareServerConn(&testConn{})
			fillServerSignal(sc)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			errC := make(chan error, 1)
			go func() {
				errC <- s.keepalive(ctx, discardLogger, sc)
			}()

			synctest.Wait()
			time.Sleep(1 * time.Second)
			synctest.Wait()

			sc.mu.Lock()
			if len(sc.wbufs) != 1 || !bytes.Equal(sc.wbufs[0], []byte{4, 0, 0, 0}) {
				t.Fatalf("wbufs: %v", sc.wbufs)
			}
			sc.mu.Unlock()
			if len(sc.wbufC) != 1 {
				t.Fatalf("len(wbufC): %d != 1", len(sc.wbufC))
			}

			cancel()
			if err := <-errC; !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		})
	})
}

func TestServer_serve_removesAllConnSubsOnReturn(t *testing.T) {
	s := mustNewServerForTest(t)

	wire := newSubFrame(1, NewPath("a"))
	err := s.serveConn(context.Background(), discardLogger, newTestConnWithBytes(wire))
	if !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}

	got := s.router.tree.Match(NewPath("a"))
	if len(got) != 0 {
		t.Fatalf("len(entries): %d != 0", len(got))
	}
}

func TestServer_serve_removesAllConnSubsOnReturn_multiplePaths(t *testing.T) {
	s := mustNewServerForTest(t)

	wire := appendFrames(
		newSubFrame(1, NewPath("a")),
		newSubFrame(2, NewPath("b")),
	)
	err := s.serveConn(context.Background(), discardLogger, newTestConnWithBytes(wire))
	if !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}

	got := s.router.tree.Match(NewPath("a"))
	if len(got) != 0 {
		t.Fatalf("len(a entries): %d != 0", len(got))
	}

	got = s.router.tree.Match(NewPath("b"))
	if len(got) != 0 {
		t.Fatalf("len(b entries): %d != 0", len(got))
	}
}
