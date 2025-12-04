package yat_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"
	"yat.io/yat"
)

var _ yat.Publisher = (*yat.Conn)(nil)
var _ yat.Requester = (*yat.Conn)(nil)
var _ yat.Subscriber = (*yat.Conn)(nil)

func TestConnPubSub(t *testing.T) {
	t.Run("fanout", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			cc := newConn(t)
			mu := new(sync.Mutex)
			mm := []yat.Msg{}

			const count = 5

			var subs []yat.Sub

			for range count {
				sub, err := cc.Subscribe(yat.Sel{Path: yat.NewPath("path")}, func(m yat.Msg) {
					mu.Lock()
					defer mu.Unlock()
					mm = append(mm, m.Clone())
				})

				if err != nil {
					t.Fatal(err)
				}

				subs = append(subs, sub)
			}

			want := yat.Msg{
				Path: yat.NewPath("path"),
				Data: []byte("hello"),
			}

			err := cc.Publish(want)
			if err != nil {
				t.Fatal(err)
			}

			synctest.Wait()
			if want, got := count, len(mm); got != want {
				t.Fatalf("len(mm): %d != %d", got, want)
			}

			for i, got := range mm {
				if diff := cmp.Diff(want, got); diff != "" {
					t.Errorf("mm[%d] differs:\n%s", i, diff)
				}
			}

			for _, s := range subs {
				s.Stop()
			}

			mm = nil
			err = cc.Publish(want)
			if err != nil {
				t.Fatal(err)
			}

			synctest.Wait()
			if len(mm) != 0 {
				t.Errorf("deliveries after stop: %d", len(mm))
			}
		})
	})

	t.Run("limit", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			cc := newConn(t)
			path := yat.NewPath("path")

			sel := yat.Sel{
				Limit: 1,
				Path:  path,
			}

			n := new(atomic.Uint64)
			_, err := cc.Subscribe(sel, func(yat.Msg) {
				n.Add(1)
			})

			if err != nil {
				t.Fatal(err)
			}

			m := yat.Msg{
				Path: path,
			}

			for range 10 {
				if err := cc.Publish(m); err != nil {
					t.Fatal(err)
				}
			}

			synctest.Wait()
			if want, got := uint64(1), n.Load(); got != want {
				t.Errorf("total received: %d != %d", got, want)
			}
		})
	})

	t.Run("group", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			cc := newConn(t)
			path := yat.NewPath("path")
			group := yat.NewGroup("group")

			sel := yat.Sel{
				Path: path,
			}

			gsel := yat.Sel{
				Path:  path,
				Group: group,
			}

			n := new(atomic.Uint64)
			f := func(yat.Msg) { n.Add(1) }

			// same group
			for range 2 {
				_, err := cc.Subscribe(gsel, f)
				if err != nil {
					t.Fatal(err)
				}
			}

			// no group
			_, err := cc.Subscribe(sel, f)
			if err != nil {
				t.Fatal(err)
			}

			m := yat.Msg{Path: path}
			if err := cc.Publish(m); err != nil {
				t.Fatal(err)
			}

			synctest.Wait()

			// only 1 of the grouped subs should receive the message
			if want, got := uint64(2), n.Load(); got != want {
				t.Errorf("total received: %d != %d", got, want)
			}
		})
	})
}

func TestConnReqRes(t *testing.T) {
	t.Run("roundtrip", func(t *testing.T) {
		cc := newConn(t)

		sel := yat.Sel{
			Path: yat.NewPath("echo"),
		}

		_, err := cc.Subscribe(sel, func(req yat.Msg) {
			res := yat.Msg{Data: bytes.Clone(req.Data), Path: req.Reply}
			if err := cc.Publish(res); err != nil {
				panic(err)
			}
		})

		if err != nil {
			t.Fatal(err)
		}

		var got []byte
		err = cc.Request(t.Context(), sel.Path, []byte("data"), func(res yat.Msg) error {
			got = bytes.Clone(res.Data)
			return nil
		})

		if err != nil {
			t.Fatal(err)
		}

		if want, got := "data", string(got); got != want {
			t.Errorf("echo response data: %q != %q", got, want)
		}
	})

	t.Run("ENOENT", func(t *testing.T) {
		cc := newConn(t)
		err := cc.Request(t.Context(), yat.NewPath("path"), nil, func(yat.Msg) error {
			panic("response received")
		})

		if err != yat.ENOENT {
			t.Error(err)
		}
	})

	t.Run("ctx canceled", func(t *testing.T) {
		cc := newConn(t)

		sel := yat.Sel{
			Path: yat.NewPath("echo-wait"),
		}

		ctx, cancel := context.WithTimeout(t.Context(), 1*time.Millisecond)
		defer cancel()

		_, err := cc.Subscribe(sel, func(req yat.Msg) { cancel() })
		if err != nil {
			t.Fatal(err)
		}

		err = cc.Request(ctx, sel.Path, nil, func(yat.Msg) error {
			panic("response received")
		})

		if ctx.Err() == nil {
			t.Fatal("not canceled")
		}

		if err != ctx.Err() {
			t.Error(err)
		}
	})

	t.Run("conn closed", func(t *testing.T) {
		cc := newConn(t)

		sel := yat.Sel{
			Path: yat.NewPath("path"),
		}

		_, err := cc.Subscribe(sel, func(req yat.Msg) {
			if err := cc.Close(); err != nil {
				panic(err)
			}
		})

		if err != nil {
			t.Fatal(err)
		}

		err = cc.Request(t.Context(), sel.Path, nil, func(res yat.Msg) error {
			panic("response received")
		})

		if !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
	})
}

func TestConnFlushing(t *testing.T) {
	t.Run("roundtrip", func(t *testing.T) {
		cc := newConn(t)
		if err := cc.Flush(t.Context()); err != nil {
			t.Error(err)
		}
	})
}

// newConn returns a new client conn
// connected to an isolated server conn
// over a synchronous pipe.
//
// It's fine to call Close on the returned conn,
// but it's not required: The client and server conns
// are cleaned up automatically after t is complete.
func newConn(t *testing.T) *yat.Conn {
	return newConnWithRouter(t, yat.NewRouter())
}

// newConnWithRouter returns a new client conn
// connected to a server conn serving the given router
// over a synchronous pipe.
//
// It's fine to call Close on the returned conn,
// but it's not required: The client and server conns
// are cleaned up automatically after t is complete.
func newConnWithRouter(t *testing.T, rr *yat.Router) *yat.Conn {
	a, b := net.Pipe()
	cc := yat.NewConn(a)
	t.Cleanup(func() { cc.Close() })
	go yat.Serve(t.Context(), b, rr)
	return cc
}

func TestConn_Publish(t *testing.T) {
	t.Run("missing path", func(t *testing.T) {
		a, _ := net.Pipe()
		cc := yat.NewConn(a)
		if err := cc.Publish(yat.Msg{}); err == nil {
			t.Error("no error")
		}
	})

	t.Run("conn closed", func(t *testing.T) {
		a, _ := net.Pipe()
		cc := yat.NewConn(a)
		if err := cc.Close(); err != nil {
			t.Fatal(err)
		}

		if err := cc.Publish(yat.Msg{Path: yat.NewPath("path")}); err != net.ErrClosed {
			t.Error(err)
		}
	})
}

func TestConn_Request(t *testing.T) {
	t.Run("missing path", func(t *testing.T) {
		a, _ := net.Pipe()
		cc := yat.NewConn(a)
		if err := cc.Request(t.Context(), yat.Path{}, nil, func(yat.Msg) error { return nil }); err == nil {
			t.Error("no error")
		}
	})

	t.Run("ctx done", func(t *testing.T) {
		a, _ := net.Pipe()
		cc := yat.NewConn(a)

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		if err := cc.Request(ctx, yat.NewPath("path"), nil, func(yat.Msg) error { return nil }); err != ctx.Err() {
			t.Error(err)
		}
	})

	t.Run("conn closed", func(t *testing.T) {
		a, _ := net.Pipe()
		cc := yat.NewConn(a)
		if err := cc.Close(); err != nil {
			t.Fatal(err)
		}

		if err := cc.Request(t.Context(), yat.NewPath("path"), nil, func(yat.Msg) error { return nil }); err != net.ErrClosed {
			t.Error(err)
		}
	})
}

func TestConn_Subscribe(t *testing.T) {
	t.Run("missing path", func(t *testing.T) {
		a, _ := net.Pipe()
		cc := yat.NewConn(a)
		if _, err := cc.Subscribe(yat.Sel{}, func(yat.Msg) {}); err == nil {
			t.Error("no error")
		}
	})

	t.Run("negative limit", func(t *testing.T) {
		cc := newConn(t)
		sel := yat.Sel{Path: yat.NewPath("path"), Limit: -1}
		if _, err := cc.Subscribe(sel, func(yat.Msg) {}); err == nil {
			t.Error("no error")
		}
	})

	t.Run("conn closed", func(t *testing.T) {
		a, _ := net.Pipe()
		cc := yat.NewConn(a)
		if err := cc.Close(); err != nil {
			t.Fatal(err)
		}

		if _, err := cc.Subscribe(yat.Sel{Path: yat.NewPath("path")}, func(yat.Msg) {}); err != net.ErrClosed {
			t.Error(err)
		}
	})
}

func TestConn_Flush(t *testing.T) {
	t.Run("ctx done", func(t *testing.T) {
		a, _ := net.Pipe()
		cc := yat.NewConn(a)

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		if err := cc.Flush(ctx); err != ctx.Err() {
			t.Error(err)
		}
	})

	t.Run("conn closed", func(t *testing.T) {
		a, _ := net.Pipe()
		cc := yat.NewConn(a)
		if err := cc.Close(); err != nil {
			t.Fatal(err)
		}

		if err := cc.Flush(t.Context()); err != net.ErrClosed {
			t.Error(err)
		}
	})
}

func TestConn_Close(t *testing.T) {
	a, _ := net.Pipe()
	cc := yat.NewConn(a)
	if err := cc.Close(); err != nil {
		t.Fatal(err)
	}

	if err := cc.Close(); err != net.ErrClosed {
		t.Error(err)
	}
}
