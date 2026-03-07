package yat

type Publisher interface {
	Publish(Msg) error
}

type Subscriber interface {
	Subscribe(Sel, func(Msg)) (Sub, error)
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
