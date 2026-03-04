package yat

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"
)

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
		t.Fatal("expected error")
	}
}

func TestServer_readFrames(t *testing.T) {
	t.Run("short frame", func(t *testing.T) {
		s := mustNewServerForTest(t)
		sc := newBareServerConn(newTestConnWithBytes([]byte{3, 0, 0, subFrameType}))

		err := s.readFrames(context.Background(), discardLogger, sc)
		if !errors.Is(err, errShortFrame) {
			t.Fatalf("error: %v", err)
		}
	})

	t.Run("unknown frame discard fails on short body", func(t *testing.T) {
		s := mustNewServerForTest(t)
		unknown := newUnknownFrame(99, []byte{1, 2})
		unknown = unknown[:len(unknown)-1]
		sc := newBareServerConn(newTestConnWithBytes(unknown))

		err := s.readFrames(context.Background(), discardLogger, sc)
		if !errors.Is(err, io.EOF) {
			t.Fatalf("error: %v", err)
		}
	})

	t.Run("unknown frame is discarded, pub frame is handled", func(t *testing.T) {
		s := mustNewServerForTest(t)
		msgC := make(chan Msg, 1)
		unsub, err := s.router.Subscribe(Sel{Path: NewPath("chat/room")}, func(m Msg) {
			msgC <- m
		})
		if err != nil {
			t.Fatal(err)
		}
		defer unsub()

		pub := appendFrame(nil, pubFrameType, func(b []byte) []byte {
			return appendMsgFields(b, Msg{
				Path:  NewPath("chat/room"),
				Data:  []byte("hi"),
				Inbox: NewPath("reply/room"),
			})
		})

		wire := appendFrames(newUnknownFrame(99, []byte{1, 2, 3}), pub)
		sc := newBareServerConn(newTestConnWithBytes(wire))

		err = s.readFrames(context.Background(), discardLogger, sc)
		if !errors.Is(err, io.EOF) {
			t.Fatalf("error: %v", err)
		}

		got := <-msgC
		if got.Path.String() != "chat/room" {
			t.Fatalf("path: %q != %q", got.Path.String(), "chat/room")
		}
		if !bytes.Equal(got.Data, []byte("hi")) {
			t.Fatalf("data: %q != %q", got.Data, "hi")
		}
		if got.Inbox.String() != "reply/room" {
			t.Fatalf("inbox: %q != %q", got.Inbox.String(), "reply/room")
		}
	})

	t.Run("known frame with short body fails read", func(t *testing.T) {
		s := mustNewServerForTest(t)
		wire := newSubFrame(1, NewPath("ok"))
		wire = wire[:len(wire)-1]
		sc := newBareServerConn(newTestConnWithBytes(wire))

		err := s.readFrames(context.Background(), discardLogger, sc)
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("error: %v", err)
		}
	})

	t.Run("handler error is returned", func(t *testing.T) {
		s := mustNewServerForTest(t)
		wire := appendFrame(nil, pubFrameType, func(b []byte) []byte { return b })
		sc := newBareServerConn(newTestConnWithBytes(wire))

		err := s.readFrames(context.Background(), discardLogger, sc)
		if !errors.Is(err, errEmptyPath) {
			t.Fatalf("error: %v", err)
		}
	})

	t.Run("dollar inbox is handled", func(t *testing.T) {
		s := mustNewServerForTest(t)
		msgC := make(chan Msg, 1)
		unsub, err := s.router.Subscribe(Sel{Path: NewPath("chat/room")}, func(m Msg) {
			msgC <- m
		})
		if err != nil {
			t.Fatal(err)
		}
		defer unsub()

		wire := appendFrame(nil, pubFrameType, func(b []byte) []byte {
			return appendMsgFields(b, Msg{
				Path:  NewPath("chat/room"),
				Inbox: NewPath("$svr/events/stop"),
			})
		})
		sc := newBareServerConn(newTestConnWithBytes(wire))

		err = s.readFrames(context.Background(), discardLogger, sc)
		if !errors.Is(err, io.EOF) {
			t.Fatalf("error: %v", err)
		}

		got := <-msgC
		if got.Path.String() != "chat/room" {
			t.Fatalf("path: %q != %q", got.Path.String(), "chat/room")
		}
		if got.Inbox.String() != "$svr/events/stop" {
			t.Fatalf("inbox: %q != %q", got.Inbox.String(), "$svr/events/stop")
		}
	})

	t.Run("sub path change error is returned", func(t *testing.T) {
		s := mustNewServerForTest(t)
		wire := appendFrames(
			newSubFrame(1, NewPath("old")),
			newSubFrame(1, NewPath("new")),
		)
		sc := newBareServerConn(newTestConnWithBytes(wire))

		err := s.readFrames(context.Background(), discardLogger, sc)
		if !errors.Is(err, errSelPath) {
			t.Fatalf("error: %v", err)
		}
	})
}

func TestServer_handlePub(t *testing.T) {
	t.Run("parse failure", func(t *testing.T) {
		s := mustNewServerForTest(t)
		err := s.handlePub(context.Background(), discardLogger, newBareServerConn(&testConn{}), []byte{0x80})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("dollar inbox is delivered", func(t *testing.T) {
		s := mustNewServerForTest(t)
		msgC := make(chan Msg, 1)
		unsub, err := s.router.Subscribe(Sel{Path: NewPath("chat/room")}, func(m Msg) {
			msgC <- m
		})
		if err != nil {
			t.Fatal(err)
		}
		defer unsub()

		body := appendMsgFields(nil, Msg{
			Path:  NewPath("chat/room"),
			Data:  []byte("hi"),
			Inbox: NewPath("$svr/events/stop"),
		})
		if err := s.handlePub(context.Background(), discardLogger, newBareServerConn(&testConn{}), body); err != nil {
			t.Fatalf("error: %v", err)
		}

		got := <-msgC
		if got.Path.String() != "chat/room" {
			t.Fatalf("path: %q != %q", got.Path.String(), "chat/room")
		}
		if !bytes.Equal(got.Data, []byte("hi")) {
			t.Fatalf("data: %q != %q", got.Data, "hi")
		}
		if got.Inbox.String() != "$svr/events/stop" {
			t.Fatalf("inbox: %q != %q", got.Inbox.String(), "$svr/events/stop")
		}
	})

	t.Run("dollar path is delivered", func(t *testing.T) {
		s := mustNewServerForTest(t)
		msgC := make(chan Msg, 1)
		unsub, err := s.router.Subscribe(Sel{Path: NewPath("$sys/pub")}, func(m Msg) {
			msgC <- m
		})
		if err != nil {
			t.Fatal(err)
		}
		defer unsub()

		body := appendMsgFields(nil, Msg{
			Path:  NewPath("$sys/pub"),
			Data:  []byte("hi"),
			Inbox: NewPath("reply/room"),
		})
		if err := s.handlePub(context.Background(), discardLogger, newBareServerConn(&testConn{}), body); err != nil {
			t.Fatal(err)
		}

		got := <-msgC
		if got.Path.String() != "$sys/pub" {
			t.Fatalf("path: %q != %q", got.Path.String(), "$sys/pub")
		}
		if !bytes.Equal(got.Data, []byte("hi")) {
			t.Fatalf("data: %q != %q", got.Data, "hi")
		}
		if got.Inbox.String() != "reply/room" {
			t.Fatalf("inbox: %q != %q", got.Inbox.String(), "reply/room")
		}
	})

	t.Run("delivers to routed subscribers", func(t *testing.T) {
		s := mustNewServerForTest(t)
		msgC := make(chan Msg, 1)
		unsub, err := s.router.Subscribe(Sel{Path: NewPath("chat/room")}, func(m Msg) {
			msgC <- m
		})
		if err != nil {
			t.Fatal(err)
		}
		defer unsub()

		body := appendMsgFields(nil, Msg{
			Path:  NewPath("chat/room"),
			Data:  []byte("hi"),
			Inbox: NewPath("reply/room"),
		})
		if err := s.handlePub(context.Background(), discardLogger, newBareServerConn(&testConn{}), body); err != nil {
			t.Fatal(err)
		}

		got := <-msgC
		if got.Path.String() != "chat/room" {
			t.Fatalf("path: %q != %q", got.Path.String(), "chat/room")
		}
		if !bytes.Equal(got.Data, []byte("hi")) {
			t.Fatalf("data: %q != %q", got.Data, "hi")
		}
		if got.Inbox.String() != "reply/room" {
			t.Fatalf("inbox: %q != %q", got.Inbox.String(), "reply/room")
		}
	})

	t.Run("denied inbox drops publish", func(t *testing.T) {
		s := mustNewServerForTest(t)
		msgC := make(chan Msg, 1)
		unsub, err := s.router.Subscribe(Sel{Path: NewPath("chat/room")}, func(m Msg) {
			msgC <- m
		})
		if err != nil {
			t.Fatal(err)
		}
		defer unsub()

		sc := newBareServerConn(&testConn{})
		sc.allow = func(p Path, a Action) bool {
			return a == ActionPub && p.Equal(NewPath("chat/room"))
		}

		body := appendMsgFields(nil, Msg{
			Path:  NewPath("chat/room"),
			Data:  []byte("hi"),
			Inbox: NewPath("reply/room"),
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
			t.Fatal("expected error")
		}
	})

	t.Run("bad path", func(t *testing.T) {
		s := mustNewServerForTest(t)
		sc := newBareServerConn(&testConn{})
		err := s.handleSub(context.Background(), discardLogger, sc, newSubFrame(1, Path{})[frameHdrLen:])
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("dollar path is routed normally", func(t *testing.T) {
		s := mustNewServerForTest(t)
		sc := newBareServerConn(&testConn{})

		if err := s.handleSub(context.Background(), discardLogger, sc, newSubFrame(1, NewPath("$sys/sub"))[frameHdrLen:]); err != nil {
			t.Fatal(err)
		}
		if len(sc.subs) != 1 {
			t.Fatalf("len(subs): %d != 1", len(sc.subs))
		}
		if _, found := sc.subs[1]; !found {
			t.Fatal("sub not found")
		}

		if err := s.router.Publish(Msg{Path: NewPath("$sys/sub"), Data: []byte("msg")}); err != nil {
			t.Fatal(err)
		}
		sc.mu.Lock()
		n := len(sc.wbufs)
		sc.mu.Unlock()
		if n == 0 {
			t.Fatal("dollar path not delivered")
		}
	})

	t.Run("changing existing sub path fails", func(t *testing.T) {
		s := mustNewServerForTest(t)
		sc := newBareServerConn(&testConn{})

		if err := s.handleSub(context.Background(), discardLogger, sc, newSubFrame(1, NewPath("old"))[frameHdrLen:]); err != nil {
			t.Fatal(err)
		}
		if err := s.handleSub(context.Background(), discardLogger, sc, newSubFrame(1, NewPath("new"))[frameHdrLen:]); !errors.Is(err, errSelPath) {
			t.Fatalf("error: %v", err)
		}

		sc.mu.Lock()
		sc.wbufs = nil
		sc.mu.Unlock()
		if err := s.router.Publish(Msg{Path: NewPath("old"), Data: []byte("live")}); err != nil {
			t.Fatal(err)
		}
		sc.mu.Lock()
		n := len(sc.wbufs)
		sc.mu.Unlock()
		if n == 0 {
			t.Fatal("old path not delivered")
		}

		sc.mu.Lock()
		sc.wbufs = nil
		sc.mu.Unlock()
		if err := s.router.Publish(Msg{Path: NewPath("new"), Data: []byte("stale")}); err != nil {
			t.Fatal(err)
		}
		sc.mu.Lock()
		n = len(sc.wbufs)
		sc.mu.Unlock()
		if n != 0 {
			t.Fatalf("new path delivered %d buffers", n)
		}
	})

	t.Run("denied sub is ignored", func(t *testing.T) {
		s := mustNewServerForTest(t)
		sc := newBareServerConn(&testConn{})
		sc.allow = func(Path, Action) bool { return false }

		if err := s.handleSub(context.Background(), discardLogger, sc, newSubFrame(1, NewPath("private/feed"))[frameHdrLen:]); err != nil {
			t.Fatal(err)
		}
		if len(sc.subs) != 0 {
			t.Fatalf("len(subs): %d != 0", len(sc.subs))
		}
	})
}

func TestServer_handleUnsub(t *testing.T) {
	t.Run("bad proto", func(t *testing.T) {
		s := mustNewServerForTest(t)
		sc := newBareServerConn(&testConn{})
		err := s.handleUnsub(context.Background(), discardLogger, sc, []byte{0xff})
		if err == nil {
			t.Fatal("expected error")
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

		if err := s.handleSub(context.Background(), discardLogger, sc, newSubFrame(1, NewPath("ok"))[frameHdrLen:]); err != nil {
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
		if err := s.router.Publish(Msg{Path: NewPath("ok"), Data: []byte("gone")}); err != nil {
			t.Fatal(err)
		}
		sc.mu.Lock()
		n := len(sc.wbufs)
		sc.mu.Unlock()
		if n != 0 {
			t.Fatalf("unsub delivered %d buffers", n)
		}
	})

	t.Run("existing dollar path sub is removed", func(t *testing.T) {
		s := mustNewServerForTest(t)
		sc := newBareServerConn(&testConn{})

		if err := s.handleSub(context.Background(), discardLogger, sc, newSubFrame(1, NewPath("$sys/ok"))[frameHdrLen:]); err != nil {
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
		if err := s.router.Publish(Msg{Path: NewPath("$sys/ok"), Data: []byte("gone")}); err != nil {
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
			t.Fatal("expected error")
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
			t.Fatalf("error: %v", err)
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
				t.Fatalf("error: %v", err)
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
				t.Fatalf("error: %v", err)
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
				t.Fatalf("error: %v", err)
			}
		})
	})
}

func TestServer_serve_removesAllConnSubsOnReturn(t *testing.T) {
	s := mustNewServerForTest(t)

	wire := newSubFrame(1, NewPath("chat/room"))
	err := s.serveConn(context.Background(), discardLogger, newTestConnWithBytes(wire))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("error: %v", err)
	}

	got := s.router.tree.Match(NewPath("chat/room"))
	if len(got) != 0 {
		t.Fatalf("len(entries): %d != 0", len(got))
	}
}

func TestServer_serve_removesAllConnSubsOnReturn_multiplePaths(t *testing.T) {
	s := mustNewServerForTest(t)

	wire := appendFrames(
		newSubFrame(1, NewPath("chat/room")),
		newSubFrame(2, NewPath("$sys/sub")),
	)
	err := s.serveConn(context.Background(), discardLogger, newTestConnWithBytes(wire))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("error: %v", err)
	}

	got := s.router.tree.Match(NewPath("chat/room"))
	if len(got) != 0 {
		t.Fatalf("len(chat entries): %d != 0", len(got))
	}

	got = s.router.tree.Match(NewPath("$sys/sub"))
	if len(got) != 0 {
		t.Fatalf("len(dollar entries): %d != 0", len(got))
	}
}
