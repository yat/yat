package yat

import (
	"iter"
	"math/rand/v2"
	"slices"
	"sync"

	"yat.io/yat/topic"
)

// Bus maintains a tree mapping topic paths to subscribers.
// It is safe to call Bus methods from multiple goroutines simultaneously.
type Bus struct {
	mu sync.RWMutex
	tt topic.Tree[*bsub]
}

// Publish delivers a copy of m to all interested subscribers before returning.
// It returns an error to satisfy [Publisher], but the error is always nil.
func (b *Bus) Publish(m Msg) error {
	if m.Topic.IsZero() {
		return nil
	}

	if ss := b.route(m); len(ss) > 0 {
		copy := m.Clone()
		for _, s := range ss {
			s.Deliver(copy)
		}
	}

	return nil
}

// Subscribe arranges for f to be called in a new goroutine when a message matching sel is published.
// It returns an error to satisfy [Subscriber], but the error is always nil.
func (b *Bus) Subscribe(sel Sel, f func(Msg)) (Subscription, error) {
	if sel.Topic.IsZero() || f == nil {
		return zsub{}, nil
	}

	deliver := func(m Msg) { go f(m) }
	sub := b.newSub(sel, deliver, nil)
	b.replace(nil, sub)
	return sub, nil
}

func (b *Bus) route(m Msg) []*bsub {
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
	return slices.DeleteFunc(ss, func(bs *bsub) bool {
		if g := bs.sel.Group; !g.IsZero() {
			if _, ok := dg[g]; ok {
				return true
			}

			if dg == nil {
				dg = map[DeliveryGroup]struct{}{}
			}

			dg[g] = struct{}{}
		}

		return flags&bs.sel.Flags != bs.sel.Flags
	})
}

// call replace to add the returned sub to the bus
func (b *Bus) newSub(sel Sel, deliver func(Msg), stop func()) *bsub {
	bs := &bsub{
		bus:   b,
		sel:   sel,
		rcv:   newReceiver(sel.Limit, deliver),
		stopC: make(chan struct{}),
		stop:  stop,
	}

	return bs
}

func (b *Bus) replace(old, new *bsub) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if old != nil {
		b.tt.Del(old.sel.Topic, old)
	}

	b.tt.Ins(new.sel.Topic, new)
}

func (b *Bus) del(bs *bsub) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tt.Del(bs.sel.Topic, bs)
}

func (b *Bus) delseq(ss iter.Seq[*bsub]) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for bs := range ss {
		b.tt.Del(bs.sel.Topic, bs)
	}
}

type bsub struct {
	bus   *Bus
	sel   Sel
	rcv   *receiver
	once  sync.Once
	stopC chan struct{}
	stop  func()
}

func (bs *bsub) Deliver(m Msg) {
	if !bs.rcv.Deliver(m) {
		bs.Stop()
	}
}

func (bs *bsub) Stop() {
	bs.once.Do(func() {
		bs.bus.del(bs)
		close(bs.stopC)
		if bs.stop != nil {
			bs.stop()
		}
	})
}

func (bs *bsub) Stopped() <-chan struct{} {
	return bs.stopC
}

// zsub is a stopped subscription.
type zsub struct{}

func (zsub) Stop() {}

func (zsub) Stopped() <-chan struct{} {
	return nil
}

type receiver struct {
	limit int

	mu      sync.Mutex
	count   int
	deliver func(Msg)
}

// newReceiver returns a new receiver with the given limit and deliver func.
// If the limit is <= 0, deliveries are unlimited.
func newReceiver(limit int, deliver func(Msg)) *receiver {
	return &receiver{limit: limit, deliver: deliver}
}

func (d *receiver) Deliver(m Msg) (ok bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	hasLimit := d.limit > 0
	if !hasLimit || d.count < d.limit {
		d.count++
		d.deliver(m)
	}

	// the limit has not been reached
	ok = !hasLimit || d.count < d.limit

	return
}

func (d *receiver) LimitReached() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.limit > 0 && d.count >= d.limit
}

// NMsg returns the number of delivered messages.
func (d *receiver) NMsg() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.count
}
