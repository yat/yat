package yat

import (
	"time"

	"github.com/yat/yat/topic"
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

// IsExpired returns true if the message deadline has passed.
func (m Msg) IsExpired() bool {
	return !m.Deadline.IsZero() && time.Now().After(m.Deadline)
}
