package yat

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/yat/yat/field"
	"github.com/yat/yat/nv"
	"github.com/yat/yat/topic"
)

func (m Msg) appendFields(b []byte) []byte {
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
		b = field.AppendTag(b, field.Num, 5)
		b = nv.Append(b, uint64(m.Deadline.UnixNano()))
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
			return fmt.Errorf("parse Msg: field %d: %v", tag.Field(), err)
		}
	}
}

func parseTopicField(t field.Tag, r *field.Reader) (parsed topic.Path, err error) {
	raw, err := parseRunField(t, r)
	if err != nil {
		return
	}
	parsed, _, err = topic.Parse(raw)
	return
}

func parseTimeField(t field.Tag, r *field.Reader) (parsed time.Time, err error) {
	ns, err := parseNumField(t, r)
	if err != nil {
		return
	}
	parsed = time.Unix(int64(ns/uint64(time.Second)), int64(ns%uint64(time.Second)))
	return
}

func parseNumField(t field.Tag, r *field.Reader) (uint64, error) {
	if t.Type() != field.Num {
		return 0, errFieldType
	}
	return r.ReadNum()
}

func parseRunField(t field.Tag, r *field.Reader) ([]byte, error) {
	if t.Type() != field.Run {
		return nil, errFieldType
	}
	return r.ReadRun()
}

var errFieldType = errors.New("invalid type")
