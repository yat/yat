package yat

import (
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
