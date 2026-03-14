package yat

import "context"

type Publisher interface {
	Publish(context.Context, Msg) error
}

type Subscriber interface {
	Subscribe(Sel, func(context.Context, Msg)) (Sub, error)
}

type PublishSubscriber interface {
	Publisher
	Subscriber
}

type Msg struct {
	Path  Path   `json:"path"`
	Data  []byte `json:"data,omitempty"`
	Inbox Path   `json:"inbox,omitzero"`
}

type Sel struct {
	Path  Path
	Group Group
	Limit int
}

type Sub interface {
	Cancel()
	Done() <-chan struct{}
}

// MaxLimit is the maximum subscription delivery limit.
const MaxLimit = 1<<16 - 1

// IsZero returns true if the selector is empty.
func (s Sel) IsZero() bool {
	return s.Path.IsZero() && s.Group.IsZero() && s.Limit == 0
}
