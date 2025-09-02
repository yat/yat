package yat

import (
	"time"

	"yat.io/yat/topic"
)

type Msg struct {

	// Topic is the address of the message.
	Topic topic.Path

	// Inbox is a path where responses can be published.
	Inbox topic.Path

	// Data holds opaque message data.
	Data []byte

	// Meta holds opaque message metadata.
	Meta []byte

	// Deadline is the instant when the message expires.
	Deadline time.Time
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
