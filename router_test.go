package yat_test

import (
	"context"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"yat.io/yat"
)

var _ yat.PublishSubscriber = new(yat.Router)
var _ yat.Requester = new(yat.Router)
var _ yat.Responder = new(yat.Router)

func TestRouterVsPathMatch(t *testing.T) {
	var tcs = []struct {
		Name    string
		Pattern string
		Path    string
	}{
		{"literal-match", "x", "x"},
		{"literal-miss", "x", "y"},
		{"single-wildcard", "*", "anything"},
		{"single-wildcard-miss", "*", "a/b"},
		{"prefix-wildcard", "x/*", "x/y"},
		{"prefix-wildcard-miss", "x/*", "x/y/z"},
		{"infix-wildcards", "*/*", "a/b"},
		{"infix-wildcards-miss", "*/*", "a"},
		{"double-star-root", "**", "x/y/z"},
		{"double-star-prefix", "x/**", "x/y/z"},
		{"double-star-prefix-min", "x/**", "x/y"},
		{"double-star-prefix-miss", "x/**", "x"},
		{"mixed-double-star", "*/**", "a/b/c"},
		{"mixed-double-star-miss", "*/**", "a"},
	}

	for _, tc := range tcs {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			pat := yat.NewPath(tc.Pattern)
			p := yat.NewPath(tc.Path)

			pmatch := pat.Match(p)

			var rmatch bool
			synctest.Test(t, func(t *testing.T) {
				rr := yat.NewRouter()

				var n atomic.Uint64
				_, err := rr.Subscribe(yat.Sel{Path: pat}, func(_ context.Context, m yat.Msg) {
					n.Add(1)
				})

				if err != nil {
					t.Fatal(err)
				}

				if err := rr.Publish(context.Background(), yat.Msg{Path: p}); err != nil {
					t.Fatal(err)
				}

				synctest.Wait()
				rmatch = n.Load() > 0
			})

			if pmatch != rmatch {
				t.Errorf("match(%q, %q): path=%v, router=%v", pat, p, pmatch, rmatch)
			}
		})
	}
}

func TestRouterFanout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			nfanoutSubs = 32
			nwildSubs   = 16
			nallSubs    = 8
			nnegSubs    = 8

			npublishers = 8
			nmsgPerPub  = 200
		)

		rr := yat.NewRouter()

		pathAB := mustPath("a/b")
		pathAC := mustPath("a/c")
		pathXY := mustPath("x/y")

		addSubs := func(sel yat.Sel, n int, handler func(context.Context, yat.Msg)) []yat.Sub {
			t.Helper()

			subs := make([]yat.Sub, 0, n)
			for range n {
				sub, err := rr.Subscribe(sel, handler)
				if err != nil {
					t.Fatalf("subscribe %q: %v", sel.Path.String(), err)
				}
				subs = append(subs, sub)
			}
			return subs
		}

		countingHandler := func(counter *atomic.Uint64) func(context.Context, yat.Msg) {
			return func(context.Context, yat.Msg) {
				counter.Add(1)
			}
		}

		var (
			fanoutCount   atomic.Uint64
			wildcardCount atomic.Uint64
			allCount      atomic.Uint64
			negativeCount atomic.Uint64
		)

		var subs []yat.Sub
		subs = append(subs, addSubs(yat.Sel{Path: pathAB}, nfanoutSubs, countingHandler(&fanoutCount))...)
		subs = append(subs, addSubs(yat.Sel{Path: mustPath("a/*")}, nwildSubs, countingHandler(&wildcardCount))...)
		subs = append(subs, addSubs(yat.Sel{Path: mustPath("**")}, nallSubs, countingHandler(&allCount))...)
		subs = append(subs, addSubs(yat.Sel{Path: mustPath("no/match")}, nnegSubs, countingHandler(&negativeCount))...)
		t.Cleanup(func() {
			for _, sub := range subs {
				sub.Cancel()
			}
		})

		for range npublishers {
			go func() {
				for j := 0; j < nmsgPerPub; j++ {
					_ = rr.Publish(context.Background(), yat.Msg{Path: pathAB})
					_ = rr.Publish(context.Background(), yat.Msg{Path: pathAC})
					_ = rr.Publish(context.Background(), yat.Msg{Path: pathXY})
				}
			}()
		}

		synctest.Wait()

		totalPerPath := npublishers * nmsgPerPub
		expectedFanout := uint64(totalPerPath * nfanoutSubs)
		expectedWildcard := uint64(totalPerPath * 2 * nwildSubs)
		expectedAll := uint64(totalPerPath * 3 * nallSubs)

		if got := fanoutCount.Load(); got != expectedFanout {
			t.Fatalf("fanout: %d != %d", got, expectedFanout)
		}
		if got := wildcardCount.Load(); got != expectedWildcard {
			t.Fatalf("wildcard: %d != %d", got, expectedWildcard)
		}
		if got := allCount.Load(); got != expectedAll {
			t.Fatalf("match-all: %d != %d", got, expectedAll)
		}
		if got := negativeCount.Load(); got != 0 {
			t.Fatalf("negative: %d != 0", got)
		}
	})
}

func TestRouter_Publish(t *testing.T) {
	bad := map[string]yat.Msg{
		"zero message": {},
		"wild path":    {Path: yat.NewPath("*")},
		"wild inbox":   {Path: yat.NewPath("path"), Inbox: yat.NewPath("*")},
	}

	for name, msg := range bad {
		t.Run(name, func(t *testing.T) {
			rr := yat.NewRouter()
			if err := rr.Publish(context.Background(), msg); err == nil {
				t.Fatal("no error")
			}
		})
	}
}

func TestRouter_Subscribe(t *testing.T) {
	bad := map[string]yat.Sel{
		"zero selector": {},
		"zero path":     {Path: yat.Path{}},
	}

	for name, sel := range bad {
		t.Run(name, func(t *testing.T) {
			rr := yat.NewRouter()
			if _, err := rr.Subscribe(sel, func(_ context.Context, m yat.Msg) {}); err == nil {
				t.Fatal("no error")
			}
		})
	}

	t.Run("nil handler", func(t *testing.T) {
		rr := yat.NewRouter()
		if _, err := rr.Subscribe(yat.Sel{Path: yat.NewPath("path")}, nil); err == nil {
			t.Error("no error")
		}
	})
}

func TestRouterRouteGroupDedupWithResponder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rr := yat.NewRouter()
		path := yat.NewPath("group/path")
		group := yat.NewGroup("g")

		res, err := rr.Respond(yat.Sel{Path: path}, func(context.Context, yat.Msg) []byte { return nil })
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(res.Cancel)

		var n1, n2 atomic.Uint64
		sub1, err := rr.Subscribe(yat.Sel{Path: path, Group: group}, func(context.Context, yat.Msg) {
			n1.Add(1)
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(sub1.Cancel)

		sub2, err := rr.Subscribe(yat.Sel{Path: path, Group: group}, func(context.Context, yat.Msg) {
			n2.Add(1)
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(sub2.Cancel)

		if err := rr.Publish(context.Background(), yat.Msg{Path: path}); err != nil {
			t.Fatal(err)
		}

		synctest.Wait()

		if got := n1.Load() + n2.Load(); got != 1 {
			t.Fatalf("grouped deliveries: %d != 1", got)
		}
	})
}

func BenchmarkRouterPublish(b *testing.B) {
	path := yat.NewPath("bench/path")
	msg := yat.Msg{Path: path}

	b.Run("subscribers-only", func(b *testing.B) {
		rr := yat.NewRouter()
		for range 8 {
			sub, err := rr.Subscribe(yat.Sel{Path: path}, func(context.Context, yat.Msg) {})
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(sub.Cancel)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := rr.Publish(context.Background(), msg); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("mixed-with-responders", func(b *testing.B) {
		rr := yat.NewRouter()
		for range 8 {
			sub, err := rr.Subscribe(yat.Sel{Path: path}, func(context.Context, yat.Msg) {})
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(sub.Cancel)
		}
		for range 8 {
			sub, err := rr.Respond(yat.Sel{Path: path}, func(context.Context, yat.Msg) []byte { return nil })
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(sub.Cancel)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := rr.Publish(context.Background(), msg); err != nil {
				b.Fatal(err)
			}
		}
	})
}
