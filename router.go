package yat

import (
	"math/rand/v2"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/google/uuid"
)

type Router struct {
	id   uuid.UUID
	mu   sync.RWMutex
	root rnode
}

func NewRouter() *Router {
	return &Router{id: uuid.New()}
}

func (rr *Router) deliver(subs []*rsub, rm rmsg) {
	var stale []*rsub
	for _, rs := range subs {
		if !rs.do(rm) {
			stale = append(stale, rs)
		}
	}

	if len(stale) > 0 {
		rr.mu.Lock()

		for _, rs := range stale {
			rr.root.Del(rs)
		}

		rr.mu.Unlock()

		for _, rs := range stale {
			if rs.Forget != nil {
				rs.Forget(rs.ID)
			}
		}
	}
}

func (rr *Router) route(m Msg) []*rsub {
	rr.mu.RLock()
	subs := rr.root.Match(m.Path)
	rr.mu.RUnlock()

	if len(subs) == 0 {
		return nil
	}

	rand.Shuffle(len(subs), func(i, j int) {
		subs[i], subs[j] = subs[j], subs[i]
	})

	var gg map[Group]struct{}
	return slices.DeleteFunc(subs, func(rs *rsub) bool {
		if lim := rs.Sel.Limit; lim > 0 && rs.n.Load() >= uint64(lim) {
			return true
		}

		if g := rs.Sel.Group; !g.IsZero() {
			if _, ok := gg[g]; ok {
				return true
			}

			if gg == nil {
				gg = map[Group]struct{}{}
			}

			gg[g] = struct{}{}
		}

		return false
	})
}

// swap updates the route tree.
// To insert a new sub, swap(nil, ns).
// To delete a sub, swap(os, nil).
// swap(nil, nil) does nothing.
func (rr *Router) swap(os *rsub, ns *rsub) {
	if os == nil && ns == nil {
		return
	}

	rr.mu.Lock()
	defer rr.mu.Unlock()

	if ns != nil {
		rr.root.Ins(ns)
	}

	if os != nil {
		rr.root.Del(os)
	}
}

// rm removes subs from the route tree.
func (rr *Router) rm(subs []*rsub) {
	rr.mu.Lock()
	defer rr.mu.Unlock()

	for _, rs := range subs {
		rr.root.Del(rs)
	}
}

type rmsg struct {
	Msg Msg
	Buf []byte
}

type rsub struct {

	// ID, if set, is passed to Deliver and Unsub.
	ID uint32

	// Sel is the message selector.
	Sel Sel

	// Deliver is called to deliver a message.
	Deliver func(id uint32, rm rmsg)

	// Forget is called after the router has deleted the sub.
	Forget func(id uint32)

	n atomic.Uint64
}

func (rs *rsub) do(rm rmsg) (ok bool) {
	lim := uint64(rs.Sel.Limit)
	ltd := lim != 0
	n := rs.n.Add(1)

	if !ltd || n <= lim {
		rs.Deliver(rs.ID, rm)
	}

	return !ltd || n < lim
}

type rnode struct {
	parent   *rnode
	name     string
	children map[string]*rnode
	subs     map[*rsub]struct{}
}

func (rn *rnode) Ins(rs *rsub) {
	l := rn.leaf(rs.Sel.Path, true)
	if l.subs == nil {
		l.subs = make(map[*rsub]struct{})
	}
	l.subs[rs] = struct{}{}
}

func (rn *rnode) Del(rs *rsub) {
	if l := rn.leaf(rs.Sel.Path, false); l != nil {
		delete(l.subs, rs)
		if l.isEmpty() {
			l.prune()
		}
	}
}

func (rn *rnode) Match(p Path) (subs []*rsub) {
	if !p.IsZero() {
		rn.match(&subs, p)
	}
	return
}

func (rn *rnode) leaf(p Path, createMissing bool) *rnode {
	car, cdr := p.cut()
	if car.IsZero() {
		return rn
	}

	if c, ok := rn.children[car.String()]; ok {
		return c.leaf(cdr, createMissing)
	}

	if !createMissing {
		return nil
	}

	if rn.children == nil {
		rn.children = make(map[string]*rnode)
	}

	c := &rnode{
		parent: rn,
		name:   car.String(),
	}

	rn.children[c.name] = c
	return c.leaf(cdr, true)
}

func (rn *rnode) match(mm *[]*rsub, p Path) {
	if p.IsZero() {
		for s := range rn.subs {
			*mm = append(*mm, s)
		}
		return
	}

	car, cdr := p.cut()
	if c, ok := rn.children[car.String()]; ok {
		c.match(mm, cdr)
	}

	if c, ok := rn.children["**"]; ok {
		c.match(mm, Path{})
	}

	if c, ok := rn.children["*"]; ok {
		c.match(mm, cdr)
	}
}

func (rn *rnode) prune() {
	ancestor := rn.parent
	name := rn.name

	for ancestor.parent != nil && len(ancestor.children) == 1 && len(ancestor.subs) == 0 {
		name = ancestor.name
		ancestor = ancestor.parent
	}

	delete(ancestor.children, name)
}

func (rn *rnode) isEmpty() bool {
	return len(rn.children) == 0 && len(rn.subs) == 0
}
