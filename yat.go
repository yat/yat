package yat

import (
	"context"

	"github.com/google/uuid"
)

type Publisher interface {
	Publish(context.Context, Msg) error
}

type Subscriber interface {
	Subscribe(context.Context, Sel, func(context.Context, Msg)) (Sub, error)
}

type PublishSubscriber interface {
	Publisher
	Subscriber
}

type Sub interface {
	// Done returns a channel that is closed
	// after the subscription stops.
	Done() <-chan struct{}
}

type Poster interface {
	Post(context.Context, Req, func(Res) error) error
}

type Handler interface {
	Handle(context.Context, Sel, func(ctx context.Context, path Path, in []byte) (out []byte)) (Sub, error)
}

type Msg struct {
	Path  Path   `json:"path"`
	Data  []byte `json:"data,omitempty"`
	Inbox Path   `json:"inbox,omitzero"`

	// uuid is a UUIDv7,
	// assigned by the server
	// after a message is received.
	uuid uuid.UUID
}

// Sel selects a set of messages.
type Sel struct {
	Path  Path
	Limit int
}

type Req struct {
	Path Path
	Data []byte

	// Limit is the maximum number of responses.
	// If the limit is 0, responses are unlimited.
	Limit int
}

type Res struct {
	Data  []byte `json:"data,omitempty"`
	Inbox Path   `json:"inbox,omitzero"`
}

// MaxDataLen is the maximum length in bytes of a message data field (4MiB - 256KiB).
const MaxDataLen = 4<<20 - 1<<18

// MsgID is a UUIDv7 identifying a delivered message.
type MsgID [16]byte

// ID returns a UUIDv7 identifying the message.
// It returns the zero ID if the message was constructed locally.
func (m Msg) ID() MsgID { return MsgID(m.uuid) }
