package yat

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/yat/yat/internal/field"
	"github.com/yat/yat/internal/nv"
	"github.com/yat/yat/topic"
)

func (m Msg) appendFields(b []byte) []byte {
	if !m.Topic.IsZero() {
		b = field.AppendTag(b, field.Run, field.One, 1)
		b = field.AppendRun(b, m.Topic.Bytes())
	}

	if !m.Inbox.IsZero() {
		b = field.AppendTag(b, field.Run, field.One, 2)
		b = field.AppendRun(b, m.Inbox.Bytes())
	}

	if len(m.Data) > 0 {
		b = field.AppendTag(b, field.Run, field.One, 3)
		b = field.AppendRun(b, m.Data)
	}

	if len(m.Meta) > 0 {
		b = field.AppendTag(b, field.Run, field.One, 4)
		b = field.AppendRun(b, m.Meta)
	}

	if !m.Deadline.IsZero() {
		b = field.AppendTag(b, field.Num, field.One, 5)
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
			m.Topic, err = parseOneTopic(tag, r)

		case 2:
			m.Inbox, err = parseOneTopic(tag, r)

		case 3:
			m.Data, err = parseOneRun(tag, r)

		case 4:
			m.Meta, err = parseOneRun(tag, r)

		case 5:
			m.Deadline, err = parseOneTime(tag, r)

		default:
			err = r.Discard(tag)
		}

		if err != nil {
			return fmt.Errorf("parse Msg: field %d (%v %v): %v",
				tag.Field(), tag.Card(), tag.Type(), err)
		}
	}
}

func parseOneTopic(t field.Tag, r *field.Reader) (parsed topic.Path, err error) {
	raw, err := parseOneRun(t, r)
	if err != nil {
		return
	}
	parsed, _, err = topic.Parse(raw)
	return
}

func parseOneTime(t field.Tag, r *field.Reader) (parsed time.Time, err error) {
	ns, err := parseOneNum(t, r)
	if err != nil {
		return
	}
	parsed = time.Unix(int64(ns/uint64(time.Second)), int64(ns%uint64(time.Second)))
	return
}

func parseOneNum(t field.Tag, r *field.Reader) (uint64, error) {
	if t.Type() != field.Num {
		return 0, errFieldType
	}

	if t.Card() != field.One {
		return 0, errFieldCard
	}

	return r.ReadNum()
}

func parseOneRun(t field.Tag, r *field.Reader) ([]byte, error) {
	if t.Type() != field.Run {
		return nil, errFieldType
	}

	if t.Card() != field.One {
		return nil, errFieldCard
	}

	return r.ReadRun()
}

var (
	errFieldType = errors.New("invalid type")
	errFieldCard = errors.New("invalid cardinality")
)
