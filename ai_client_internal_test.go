package yat

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestClient_NewClient(t *testing.T) {
	t.Run("nil dial", func(t *testing.T) {
		_, err := NewClient(nil, ClientConfig{})
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestClient_Close(t *testing.T) {
	c := newBareClient()
	close(c.doneC)
	close(c.connC)

	if err := c.Close(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("error: %v", err)
	}
}

func TestClient_Publish_validationAndClosed(t *testing.T) {
	c := newBareClient()

	if err := c.Publish(Msg{}); !errors.Is(err, errEmptyPath) {
		t.Fatalf("empty path: %v", err)
	}
	if err := c.Publish(Msg{Path: NewPath("*")}); !errors.Is(err, errWildPath) {
		t.Fatalf("wild path: %v", err)
	}
	if err := c.Publish(Msg{Path: NewPath("ok"), Inbox: NewPath("*")}); !errors.Is(err, errWildInbox) {
		t.Fatalf("wild inbox: %v", err)
	}
	if err := c.Publish(Msg{Path: NewPath("ok"), Inbox: NewPath("$svr/events/stop")}); !errors.Is(err, errReservedInbox) {
		t.Fatalf("reserved inbox: %v", err)
	}

	tooLongData := make([]byte, MaxFrameLen)
	if err := c.Publish(Msg{Path: NewPath("ok"), Data: tooLongData}); !errors.Is(err, errLongFrame) {
		t.Fatalf("long frame: %v", err)
	}

	close(c.doneC)
	if err := c.Publish(Msg{Path: NewPath("ok")}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed: %v", err)
	}
}

func TestClient_Subscribe_validationAndUnsubPaths(t *testing.T) {
	t.Run("validation", func(t *testing.T) {
		c := newBareClient()

		if _, err := c.Subscribe(Sel{}, func(Msg) {}); !errors.Is(err, errEmptyPath) {
			t.Fatalf("empty path: %v", err)
		}
		if _, err := c.Subscribe(Sel{Path: NewPath("ok")}, nil); !errors.Is(err, errNilCallback) {
			t.Fatalf("nil callback: %v", err)
		}

		close(c.doneC)
		if _, err := c.Subscribe(Sel{Path: NewPath("ok")}, func(Msg) {}); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("closed: %v", err)
		}
	})

	t.Run("signal channel already full", func(t *testing.T) {
		c := newBareClient()
		fillClientSignal(c)

		unsub, err := c.Subscribe(Sel{Path: NewPath("ok")}, func(Msg) {})
		if err != nil {
			t.Fatal(err)
		}
		if len(c.wbufC) != 1 {
			t.Fatalf("len(wbufC): %d != 1", len(c.wbufC))
		}

		unsub()
		if len(c.wbufC) != 1 {
			t.Fatalf("len(wbufC): %d != 1", len(c.wbufC))
		}
	})

	t.Run("unsub after close is a no-op", func(t *testing.T) {
		c := newBareClient()
		unsub, err := c.Subscribe(Sel{Path: NewPath("ok")}, func(Msg) {})
		if err != nil {
			t.Fatal(err)
		}
		if len(c.subs) != 1 {
			t.Fatalf("len(subs): %d != 1", len(c.subs))
		}

		close(c.doneC)
		unsub()
		if len(c.subs) != 1 {
			t.Fatalf("len(subs): %d != 1", len(c.subs))
		}
	})
}

func TestClient_readFrames(t *testing.T) {
	t.Run("short frame", func(t *testing.T) {
		c := newBareClient()
		conn := newTestConnWithBytes([]byte{3, 0, 0, msgFrameType})
		err := c.readFrames(context.Background(), discardLogger, conn)
		if !errors.Is(err, errShortFrame) {
			t.Fatalf("error: %v", err)
		}
	})

	t.Run("unknown frame discard fails on short body", func(t *testing.T) {
		c := newBareClient()
		unknown := newUnknownFrame(99, []byte{1, 2})
		unknown = unknown[:len(unknown)-1]

		err := c.readFrames(context.Background(), discardLogger, newTestConnWithBytes(unknown))
		if !errors.Is(err, io.EOF) {
			t.Fatalf("error: %v", err)
		}
	})

	t.Run("unknown frame is discarded, known msg is handled", func(t *testing.T) {
		c := newBareClient()
		msgC := make(chan Msg, 1)
		c.subs[7] = &clientSub{
			Do: func(m Msg) { msgC <- m },
		}

		msg := Msg{Path: NewPath("chat/room"), Data: []byte("hi"), Inbox: NewPath("reply/room")}
		wire := appendFrames(
			newUnknownFrame(99, []byte{1, 2, 3}),
			newMsgFrame(7, msg),
		)

		err := c.readFrames(context.Background(), discardLogger, newTestConnWithBytes(wire))
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

	t.Run("known msg with short body fails read", func(t *testing.T) {
		c := newBareClient()
		wire := newMsgFrame(1, Msg{Path: NewPath("ok")})
		wire = wire[:len(wire)-1]

		err := c.readFrames(context.Background(), discardLogger, newTestConnWithBytes(wire))
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("error: %v", err)
		}
	})

	t.Run("handler error is returned", func(t *testing.T) {
		c := newBareClient()
		wire := appendFrame(nil, msgFrameType, func(b []byte) []byte { return b })

		err := c.readFrames(context.Background(), discardLogger, newTestConnWithBytes(wire))
		if !errors.Is(err, errEmptyPath) {
			t.Fatalf("error: %v", err)
		}
	})
}

func TestClient_handleMsg(t *testing.T) {
	c := newBareClient()
	err := c.handleMsg(context.Background(), discardLogger, []byte{0x80})
	if err == nil {
		t.Fatal("expected error")
	}
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
			t.Fatalf("error: %v", err)
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
			t.Fatalf("error: %v", err)
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
				t.Fatalf("error: %v", err)
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
				t.Fatalf("error: %v", err)
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
				t.Fatalf("error: %v", err)
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

			subPath := NewPath("chat/resub")
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
}
