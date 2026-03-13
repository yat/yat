package yat

import (
	"context"
	"errors"
	"math/rand/v2"
	"slices"
	"sync"
	"sync/atomic"
)

// Router delivers messages to interested subscribers.
type Router struct {
	mu   sync.RWMutex
	tree rnode
}

// A delivery is received and distributed by the router.
type delivery struct {
	Msg Msg

	// Raw, if set, holds the protowire-encoded fields backing Msg.
	// On the server, this buffer is used for efficient fanout.
	// Raw is not used by the client.
	Raw []byte

	// Ctx holds the delivery context.
	// If it is not nil, it is passed to callbacks instead of [context.Background].
	Ctx context.Context
}

// rnode implements a simple prefix tree.
// Empty branches are pruned on delete.
//
// It should be replaced with something that:
//   - is faster and more memory efficient
//   - doesn't churn on quick ins/del
type rnode struct {
	parent   *rnode
	name     string
	children map[string]*rnode
	entries  []*rent

	// cached for fast lookup
	wildElem, wildSuffix *rnode
}

// rent is an entry in the route tree.
type rent struct {
	Ext bool
	Sel Sel
	Do  func(delivery)
	n   atomic.Uint64

	ltd   atomic.Bool
	doneC chan struct{}
	unsub func()
}

// rop is a router operation.
// rops are applied in batches by update.
type rop struct {
	Type  ropType
	Entry *rent
}

type ropType bool

const (
	ropIns ropType = true
	ropDel ropType = false
)

var errNilCallback = errors.New("nil callback func")

// NewRouter initializes and returns a new router.
func NewRouter() *Router {
	return &Router{}
}

// Pub publishes the message.
// It is an error to change a message after pubishing it.
func (rr *Router) Publish(ctx context.Context, m Msg) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if err := validateMsg(m); err != nil {
		return err
	}

	ee, ext := rr.route(m.Path)
	if len(ee) == 0 {
		return nil
	}

	d := delivery{
		Ctx: ctx,
		Msg: m,
	}

	if ext {
		// make a deep copy to fanout
		d.Raw = appendMsgFields(nil, d.Msg)
		d.Msg = aliasMsgFields(d.Raw)
	}

	rr.deliver(ee, d)

	return nil
}

// Subscribe arranges for the callback func to be called in a new goroutine
// when a selected message is published.
//
// Call [Sub.Cancel] to unsubscribe.
//
// The callback func must not retain or modify delivered messages.
func (rr *Router) Subscribe(sel Sel, callback func(context.Context, Msg)) (Sub, error) {
	if err := validateSel(sel); err != nil {
		return nil, err
	}

	if callback == nil {
		return nil, errNilCallback
	}

	e := &rent{
		Sel: sel,
		Do: func(d delivery) {
			ctx := d.Ctx
			if ctx == nil {
				ctx = context.Background()
			}
			go callback(ctx, d.Msg)
		},

		doneC: make(chan struct{}),
	}

	e.unsub = sync.OnceFunc(func() {
		close(e.doneC)
		if !e.ltd.Load() {
			rr.update(rop{ropDel, e})
		}
	})

	rr.update(rop{ropIns, e})
	return e, nil
}

func (rr *Router) update(batch ...rop) {
	if len(batch) == 0 {
		return
	}

	rr.mu.Lock()
	defer rr.mu.Unlock()

	for _, op := range batch {
		switch op.Type {
		case ropIns:
			rr.tree.Ins(op.Entry)

		case ropDel:
			rr.tree.Del(op.Entry)
		}
	}
}

func (rr *Router) route(path Path) (entries []*rent, external bool) {
	rr.mu.RLock()
	ee := rr.tree.Match(path)
	rr.mu.RUnlock()

	if len(ee) == 0 {
		return
	}

	rand.Shuffle(len(ee), func(i, j int) {
		ee[i], ee[j] = ee[j], ee[i]
	})

	var gg map[Group]struct{}
	entries = slices.DeleteFunc(ee, func(e *rent) bool {
		if g := e.Sel.Group; g != (Group{}) {
			if _, filled := gg[g]; filled {
				return true
			}

			if gg == nil {
				gg = map[Group]struct{}{}
			}

			// fill the slot
			gg[g] = struct{}{}
		}

		if e.Ext {
			external = true
		}

		return false
	})

	return
}

func (rr *Router) deliver(ee []*rent, d delivery) {
	var ops []rop
	for _, e := range ee {
		n := e.n.Add(1)
		lim := uint64(e.Sel.Limit)

		if lim == 0 || n <= lim {
			e.Do(d)
		}

		if lim > 0 && n >= lim {
			ops = append(ops, rop{ropDel, e})
		}
	}

	for _, op := range ops {
		op.Entry.ltd.Store(true)
		op.Entry.unsub()
	}

	rr.update(ops...)
}

// Ins inserts e into the tree.
// Calls to Match will consider e.
func (n *rnode) Ins(e *rent) {
	n.leaf(e.Sel.Path, true).ins(e)
}

// Del removes e from the tree.
func (n *rnode) Del(e *rent) {
	if l := n.leaf(e.Sel.Path, false); l != nil {
		l.del(e)
	}
}

// Match returns the entries with patterns matching p.
func (n *rnode) Match(p Path) (entries []*rent) {
	if p.IsZero() {
		return
	}

	n.match(&entries, p)
	return
}

func (n *rnode) leaf(p Path, createMissing bool) *rnode {
	car, cdr := p.cut()
	if car.IsZero() {
		return n
	}

	name := car.String()

	var c *rnode
	switch name {
	case "*":
		c = n.wildElem

	case "**":
		c = n.wildSuffix

	default:
		c = n.children[name]
	}

	if c != nil {
		return c.leaf(cdr, createMissing)
	}

	if !createMissing {
		return nil
	}

	if n.children == nil {
		n.children = make(map[string]*rnode)
	}

	c = &rnode{
		parent: n,
		name:   name,
	}

	n.children[name] = c
	switch name {
	case "*":
		n.wildElem = c

	case "**":
		n.wildSuffix = c
	}

	return c.leaf(cdr, true)
}

func (n *rnode) ins(e *rent) {
	n.entries = append(n.entries, e)
}

func (n *rnode) del(v *rent) {
	if i := slices.Index(n.entries, v); i >= 0 {
		j := len(n.entries) - 1

		// overwrite
		n.entries[i] = n.entries[j]
		n.entries[j] = nil

		// trim
		n.entries = n.entries[:j]
	}

	// prune empty branches
	if len(n.children) == 0 && len(n.entries) == 0 {
		ancestor := n.parent
		name := n.name

		for ancestor.parent != nil && len(ancestor.children) == 1 && len(ancestor.entries) == 0 {
			name = ancestor.name
			ancestor = ancestor.parent
		}

		delete(ancestor.children, name)
		switch name {
		case "*":
			ancestor.wildElem = nil

		case "**":
			ancestor.wildSuffix = nil
		}
	}
}

func (n *rnode) match(ee *[]*rent, p Path) {
	if p.IsZero() {
		*ee = append(*ee, n.entries...)
		return
	}

	car, cdr := p.cut()
	if c, ok := n.children[car.String()]; ok {
		c.match(ee, cdr)
	}

	if n.wildSuffix != nil {
		n.wildSuffix.match(ee, Path{})
	}

	if n.wildElem != nil {
		n.wildElem.match(ee, cdr)
	}
}

func (e *rent) Cancel() {
	e.unsub()
}

func (e *rent) Done() <-chan struct{} {
	return e.doneC
}
