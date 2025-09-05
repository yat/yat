package yat

import (
	"bytes"
	"slices"
	"time"

	"yat.io/yat/topic"
)

type Msg struct {

	// Topic is the address of the message.
	Topic topic.Path `json:"topic,omitzero"`

	// Inbox is a path where responses can be published.
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

// Topic creates a topic path from a raw value.
// If the value is a byte slice, it is aliased by the returned path.
// If the path is invalid, Topic panics.
func Topic[V ~[]byte | ~string](raw V) topic.Path {
	p, _, err := topic.Parse(raw)
	if err != nil {
		panic(err)
	}
	return p
}

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
	return Msg{
		Topic:    m.Topic.Clone(),
		Inbox:    m.Inbox.Clone(),
		Data:     slices.Clone(m.Data),
		Meta:     slices.Clone(m.Meta),
		Deadline: m.Deadline,
	}
}
