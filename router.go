package yat

import (
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
	entries  map[*rent]struct{}
}

// rent is an entry in the route tree.
type rent struct {
	Sel Sel
	Do  func(Msg, []byte)
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

// Pub publishes a copy of the message.
func (rr *Router) Publish(m Msg) error {
	if err := validateMsg(m); err != nil {
		return err
	}

	ee := rr.route(m.Path)
	if len(ee) == 0 {
		return nil
	}

	m, raw := cloneMsg(m)
	rr.deliver(ee, m, raw)

	return nil
}

// Subscribe arranges for the callback func to be called in a new goroutine
// when a selected message is published.
//
// Call [Sub.Cancel] to unsubscribe.
//
// The callback func must not retain or modify delivered messages.
func (rr *Router) Subscribe(sel Sel, callback func(Msg)) (Sub, error) {
	if err := validateSel(sel); err != nil {
		return nil, err
	}

	if callback == nil {
		return nil, errNilCallback
	}

	e := &rent{
		Sel: sel,
		Do: func(m Msg, _ []byte) {
			go callback(m)
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

func (rr *Router) route(path Path) []*rent {
	rr.mu.RLock()
	ee := rr.tree.Match(path)
	rr.mu.RUnlock()

	if len(ee) == 0 {
		return nil
	}

	rand.Shuffle(len(ee), func(i, j int) {
		ee[i], ee[j] = ee[j], ee[i]
	})

	var gg map[Group]struct{}
	return slices.DeleteFunc(ee, func(e *rent) bool {
		if g := e.Sel.Group; g.String() != "" { // FIX: IsZero
			if _, filled := gg[g]; filled {
				return true
			}

			if gg == nil {
				gg = map[Group]struct{}{}
			}

			// fill the slot
			gg[g] = struct{}{}
		}

		return false
	})
}

func (rr *Router) deliver(ee []*rent, m Msg, raw []byte) {
	var ops []rop
	for _, e := range ee {
		n := e.n.Add(1)
		lim := uint64(e.Sel.Limit)

		if lim == 0 || n <= lim {
			e.Do(m, raw)
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

	if c, ok := n.children[car.String()]; ok {
		return c.leaf(cdr, createMissing)
	}

	if !createMissing {
		return nil
	}

	if n.children == nil {
		n.children = make(map[string]*rnode)
	}

	c := &rnode{
		parent: n,
		name:   car.String(),
	}

	n.children[c.name] = c
	return c.leaf(cdr, true)
}

func (n *rnode) ins(e *rent) {
	if n.entries == nil {
		n.entries = make(map[*rent]struct{})
	}

	n.entries[e] = struct{}{}
}

func (n *rnode) del(v *rent) {
	delete(n.entries, v)

	// prune empty branches
	if len(n.children) == 0 && len(n.entries) == 0 {
		ancestor := n.parent
		name := n.name

		for ancestor.parent != nil && len(ancestor.children) == 1 && len(ancestor.entries) == 0 {
			name = ancestor.name
			ancestor = ancestor.parent
		}

		delete(ancestor.children, name)
	}
}

func (n *rnode) match(ee *[]*rent, p Path) {
	if p.IsZero() {
		for v := range n.entries {
			*ee = append(*ee, v)
		}
		return
	}

	car, cdr := p.cut()
	if c, ok := n.children[car.String()]; ok {
		c.match(ee, cdr)
	}

	if c, ok := n.children["**"]; ok {
		c.match(ee, Path{})
	}

	if c, ok := n.children["*"]; ok {
		c.match(ee, cdr)
	}
}

func (e *rent) Cancel() {
	e.unsub()
}

func (e *rent) Done() <-chan struct{} {
	return e.doneC
}
