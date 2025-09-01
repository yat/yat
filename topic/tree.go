package topic

import (
	"iter"
)

type Tree[V comparable] struct {
	parent   *Tree[V]
	name     string
	children map[string]*Tree[V]
	subs     map[V]struct{}
}

func (tt *Tree[V]) Ins(pattern Path, value V) {
	l := tt.leaf(pattern, true)
	if l.subs == nil {
		l.subs = make(map[V]struct{})
	}
	l.subs[value] = struct{}{}
}

func (tt *Tree[V]) Del(pattern Path, value V) {
	if l := tt.leaf(pattern, false); l != nil {
		delete(l.subs, value)
		if l.isEmpty() {
			l.prune()
		}
	}
}

func (tt *Tree[V]) Matches(p Path) iter.Seq[V] {
	return func(yield func(V) bool) {
		wild := !p.IsZero() && p.buf[0] != '.'
		tt.match(p, wild, yield)
	}
}

func (tt *Tree[V]) leaf(p Path, createMissing bool) *Tree[V] {
	car, cdr := p.cut()
	if car.IsZero() {
		return tt
	}

	if c, ok := tt.children[car.String()]; ok {
		return c.leaf(cdr, createMissing)
	}

	if !createMissing {
		return nil
	}

	// FIX: it seems like it would be faster to create the missing
	// subtree here iteratively instead of recursing

	if tt.children == nil {
		tt.children = make(map[string]*Tree[V])
	}

	c := &Tree[V]{
		parent: tt,
		name:   car.String(),
	}

	tt.children[c.name] = c
	return c.leaf(cdr, true)
}

func (tt *Tree[V]) match(p Path, wild bool, yield func(V) bool) {
	if p.IsZero() {
		for s := range tt.subs {
			if !yield(s) {
				return
			}
		}
		return
	}

	car, cdr := p.cut()
	if c, ok := tt.children[car.String()]; ok {
		c.match(cdr, wild, yield)
	}

	if wild {
		if c, ok := tt.children["**"]; ok {
			c.match(Path{}, false, yield)
		}

		if c, ok := tt.children["*"]; ok {
			c.match(cdr, wild, yield)
		}
	}
}

func (tt *Tree[V]) prune() {
	ancestor := tt.parent
	name := tt.name

	for ancestor.parent != nil && len(ancestor.children) == 1 && len(ancestor.subs) == 0 {
		name = ancestor.name
		ancestor = ancestor.parent
	}

	delete(ancestor.children, name)
}

func (tt *Tree[V]) isEmpty() bool {
	return len(tt.children) == 0 && len(tt.subs) == 0
}
