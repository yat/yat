package yat

import (
	"crypto/rand"
	"encoding/hex"
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

// Inbox returns a random topic path like "@8952/eb0b/8e18151af00e5bcfc13c75ea".
func Inbox() topic.Path {
	raw := make([]byte, 16)
	rand.Read(raw)
	inb := make([]byte, len(raw)*2+3)

	inb[0] = '@'
	hex.Encode(inb[1:5], raw[0:2])
	inb[5] = '/'
	hex.Encode(inb[6:10], raw[2:4])
	inb[10] = '/'
	hex.Encode(inb[11:], raw[4:])
	return topic.New(inb)
}

// IsExpired returns true if the message deadline has passed.
func (m Msg) IsExpired() bool {
	return !m.Deadline.IsZero() && time.Now().After(m.Deadline)
}
