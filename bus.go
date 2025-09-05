package yat

import (
	"iter"
	"math/rand/v2"
	"slices"
	"sync"
	"sync/atomic"

	"yat.io/yat/topic"
)

// Bus maintains a tree mapping topic paths to subscribers.
// It is safe to call Bus methods from multiple goroutines simultaneously.
type Bus struct {
	mu sync.RWMutex
	tt topic.Tree[*subscription]
}

// Publish delivers a copy of m to all interested subscribers before returning.
// It returns an error to satisfy [Publisher], but the error is always nil.
func (b *Bus) Publish(m Msg) error {
	if m.Topic.IsZero() {
		return nil
	}

	b.deliver(m.Clone())

	return nil
}

// Subscribe arranges for f to be called in a new goroutine when a message matching sel is published.
// It returns an error to satisfy [Subscriber], but the error is always nil.
func (b *Bus) Subscribe(sel Sel, f func(Msg)) (Subscription, error) {
	if sel.Topic.IsZero() || f == nil {
		return zeroSub{}, nil
	}

	sub := newSub(sel, func(m Msg) { go f(m) }, b.del)
	b.ins(sub, nil)

	return sub, nil
}

func (b *Bus) deliver(m Msg) (n int) {
	ss := b.route(m)
	for _, s := range ss {
		s.Deliver(m)
	}

	return len(ss)
}

func (b *Bus) route(m Msg) []*subscription {
	if m.Topic.IsZero() {
		return nil
	}

	var flags SelFlags
	if len(m.Data) > 0 {
		flags |= DATA
	}

	if !m.Inbox.IsZero() {
		flags |= INBOX
	}

	b.mu.RLock()
	ss := slices.Collect(b.tt.Matches(m.Topic))
	b.mu.RUnlock()

	rand.Shuffle(len(ss), func(i, j int) {
		ss[i], ss[j] = ss[j], ss[i]
	})

	var dg map[DeliveryGroup]struct{}
	return slices.DeleteFunc(ss, func(s *subscription) bool {
		if g := s.sel.Group; !g.IsZero() {
			if _, ok := dg[g]; ok {
				return true
			}

			if dg == nil {
				dg = map[DeliveryGroup]struct{}{}
			}

			dg[g] = struct{}{}
		}

		return flags&s.sel.Flags != s.sel.Flags
	})
}

func (b *Bus) ins(s *subscription, del *subscription) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if del != nil {
		b.tt.Del(del.sel.Topic, del)
	}

	b.tt.Ins(s.sel.Topic, s)
}

func (b *Bus) del(s *subscription) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tt.Del(s.sel.Topic, s)
}

func (b *Bus) delseq(ss iter.Seq[*subscription]) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for s := range ss {
		b.tt.Del(s.sel.Topic, s)
	}
}

type subscription struct {
	sel Sel

	deliver    func(Msg)
	deliveries atomic.Uint64

	stop  func()
	stopC chan struct{}
}

func newSub(sel Sel, deliver func(Msg), cleanup func(*subscription)) *subscription {
	sub := &subscription{
		sel:     sel,
		deliver: deliver,
		stopC:   make(chan struct{}),
	}

	sub.stop = sync.OnceFunc(func() {
		close(sub.stopC)
		cleanup(sub)
	})

	return sub
}

func (s *subscription) Deliver(m Msg) {
	n := s.deliveries.Add(1)
	lim := uint64(s.sel.Limit)
	ltd := lim > 0

	if !ltd || n <= lim {
		s.deliver(m)
	}

	if ltd && n >= lim {
		s.Stop()
	}
}

func (s *subscription) Stop() {
	s.stop()
}

func (s *subscription) Stopped() <-chan struct{} {
	return s.stopC
}

// zeroSub is a stopped subscription.
type zeroSub struct{}

func (zeroSub) Stop() {}

func (zeroSub) Stopped() <-chan struct{} {
	return nil
}
