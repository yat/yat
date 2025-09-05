package yat

import (
	"bytes"
	"fmt"
	"io"
	"slices"
	"time"

	"yat.io/yat/field"
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
	var raw []byte

	switch {
	case m.fields != nil:
		raw = slices.Clone(*m.fields)

	default:
		raw = m.appendFields(nil)
	}

	var c Msg
	if err := c.parseFields(field.NewReader(raw)); err != nil {
		panic(err)
	}

	return c
}

func (m Msg) appendFields(b []byte) []byte {
	if m.fields != nil {
		return append(b, *m.fields...)
	}

	if !m.Topic.IsZero() {
		b = field.AppendTag(b, field.Run, 1)
		b = field.AppendRun(b, m.Topic.Bytes())
	}

	if !m.Inbox.IsZero() {
		b = field.AppendTag(b, field.Run, 2)
		b = field.AppendRun(b, m.Inbox.Bytes())
	}

	if len(m.Data) > 0 {
		b = field.AppendTag(b, field.Run, 3)
		b = field.AppendRun(b, m.Data)
	}

	if len(m.Meta) > 0 {
		b = field.AppendTag(b, field.Run, 4)
		b = field.AppendRun(b, m.Meta)
	}

	if !m.Deadline.IsZero() {
		b = field.AppendTag(b, field.Value, 5)
		b = field.AppendValue(b, uint64(m.Deadline.UnixNano()))
	}

	return b
}

func (m *Msg) parseFields(r *field.Reader) error {
	for {
		tag, err := r.ReadTag()
		if err == io.EOF {
			return nil
		}

		if err != nil {
			return err
		}

		switch tag.Field() {

		// these cases are duplicated in pkgFrameBody.ParseFields

		case 1:
			m.Topic, err = parseTopicField(tag, r)

		case 2:
			m.Inbox, err = parseTopicField(tag, r)

		case 3:
			m.Data, err = parseRunField(tag, r)

		case 4:
			m.Meta, err = parseRunField(tag, r)

		case 5:
			m.Deadline, err = parseTimeField(tag, r)

		default:
			err = r.Discard(tag)
		}

		if err != nil {
			return fmt.Errorf("parse message field %d: %v", tag.Field(), err)
		}
	}
}
