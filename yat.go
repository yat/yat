package yat

import (
	"bytes"
	"fmt"
	"slices"
	"time"
	"unique"

	"yat.io/yat/topic"
)

type Publisher interface {
	Publish(Msg) error
}

type Subscriber interface {
	Subscribe(Sel, SubFlags, func(Msg)) (Subscription, error)
}

type Subscription interface {
	Stopped() <-chan struct{}
	Stop()
}

type Msg struct {

	// Topic is the address of the message.
	Topic topic.Path `json:"topic,omitzero"`

	// Inbox is an address where responses can be published.
	Inbox topic.Path `json:"inbox,omitzero"`

	// Data holds opaque message data.
	Data []byte `json:"data,omitzero"`

	// Meta holds opaque message metadata.
	Meta []byte `json:"meta,omitzero"`

	// Deadline is the instant when the message expires.
	Deadline time.Time `json:"deadline,omitzero"`

	// fields is set by the server when it decodes a message frame, or by the bus when
	// a message is published directly. When the message is delivered, the referenced
	// slice is appended to each subscribing connection's write buffer list instead of
	// copying or re-encoding the message for each subscriber.
	//
	// It is a pointer to keep Msg in Go's 128-byte allocation size class.
	fields *[]byte
}

type Sel struct {
	Topic topic.Path    `json:"topic,omitzero"`
	Limit int           `json:"limit,omitzero"`
	Group DeliveryGroup `json:"group,omitzero"`
}

type DeliveryGroup struct {
	h unique.Handle[string]
}

// SubFlags is a set of advisory subscription flags.
// A client can set flags to request special treatment from the server.
type SubFlags uint64

const (
	SubFlagResponder = SubFlags(1 << iota) // will respond, needs an inbox
)

// Equal returns true if the messages are equal.
func (m Msg) Equal(other Msg) bool {
	return m.Topic.Equal(other.Topic) &&
		m.Inbox.Equal(other.Inbox) &&
		bytes.Equal(m.Data, other.Data) &&
		bytes.Equal(m.Meta, other.Meta) &&
		m.Deadline.Equal(other.Deadline)
}

// IsExpired returns true if the message deadline has passed.
func (m Msg) IsExpired() bool {
	return !m.Deadline.IsZero() && time.Now().After(m.Deadline)
}

// Clone returns a copy of the message.
func (m Msg) Clone() Msg {
	var raw []byte

	switch {
	case m.fields != nil:
		raw = slices.Clone(*m.fields)

	default:
		raw = m.appendFields(nil)
	}

	var c Msg
	if err := c.parseFields(raw); err != nil {
		panic(err)
	}

	return c
}

// Topic creates a topic path from a string.
// If the path is invalid, Topic panics.
func Topic(s string) topic.Path {
	p, _, err := topic.Parse(s)
	if err != nil {
		panic(err)
	}
	return p
}

// Group returns the delivery group representing the given value.
// The zero group is returned if len(value) is 0.
func Group[T ~[]byte | ~string](value T) DeliveryGroup {
	if len(value) == 0 {
		return DeliveryGroup{}
	}
	return DeliveryGroup{unique.Make(string(value))}
}

// IsZero returns true if the g is the zero group.
func (g DeliveryGroup) IsZero() bool {
	return g == DeliveryGroup{}
}

// Equal returns true if the groups are equal.
// It is exactly the same operation as g == other.
func (g DeliveryGroup) Equal(other DeliveryGroup) bool {
	return g == other
}

// String returns the name of the group.
func (g DeliveryGroup) String() string {
	if g.IsZero() {
		return ""
	}
	return g.h.Value()
}

// String returns the name of the flag,
// or "SubFlag(x)" if more than one flag is set.
func (f SubFlags) String() string {
	switch f {
	case SubFlagResponder:
		return "Responder"

	default:
		return fmt.Sprintf("SubFlags(%d)", f)
	}
}
