package yat

import (
	"errors"
	"fmt"
	"io"
	"time"

	"yat.io/yat/field"
	"yat.io/yat/topic"
)

type msgFrameBody struct {
	Msg Msg
}

type subFrameBody struct {
	Num uint64
	Sel Sel
}

type unsubFrameBody struct {
	Num uint64
}

type pkgFrameBody struct {
	Num uint64
	Msg Msg
}

const (
	msgFrame   = 2
	subFrame   = 3
	unsubFrame = 4
	pkgFrame   = 128
)

// The parse methods in this file don't clear self before parsing.

func (f msgFrameBody) AppendBody(b []byte) []byte {
	return f.Msg.appendFields(b)
}

func (f *msgFrameBody) ParseFields(r *field.Reader) error {
	return f.Msg.parseFields(r)
}

func (f subFrameBody) AppendBody(b []byte) []byte {
	if f.Num > 0 {
		b = field.AppendTag(b, field.Value, 1)
		b = field.AppendValue(b, f.Num)
	}

	if !f.Sel.Topic.IsZero() {
		b = field.AppendTag(b, field.Run, 2)
		b = field.AppendRun(b, f.Sel.Topic.Bytes())
	}

	if f.Sel.Limit > 0 {
		b = field.AppendTag(b, field.Value, 3)
		b = field.AppendValue(b, uint64(f.Sel.Limit))
	}

	if !f.Sel.Group.IsZero() {
		b = field.AppendTag(b, field.Run, 4)
		b = field.AppendRun(b, []byte(f.Sel.Group.String()))
	}

	if f.Sel.Flags > 0 {
		b = field.AppendTag(b, field.Value, 5)
		b = field.AppendValue(b, uint64(f.Sel.Flags))
	}

	return b
}

func (f *subFrameBody) ParseFields(r *field.Reader) error {
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
			f.Num, err = parseNumField(tag, r)

		case 2:
			f.Sel.Topic, err = parseTopicField(tag, r)

		case 3:
			f.Sel.Limit, err = parseIntField(tag, r)

		case 4:
			f.Sel.Group, err = parseGroupField(tag, r)

		case 5:
			f.Sel.Flags, err = parseSelFlagsField(tag, r)

		default:
			err = r.Discard(tag)
		}

		if err != nil {
			return fmt.Errorf("parse sub frame body field %d: %v", tag.Field(), err)
		}
	}
}

func (f unsubFrameBody) AppendBody(b []byte) []byte {
	if f.Num > 0 {
		b = field.AppendTag(b, field.Value, 1)
		b = field.AppendValue(b, f.Num)
	}

	return b
}

func (f *unsubFrameBody) ParseFields(r *field.Reader) error {
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
			f.Num, err = parseNumField(tag, r)

		default:
			err = r.Discard(tag)
		}

		if err != nil {
			return fmt.Errorf("parse unsub frame body field %d: %v", tag.Field(), err)
		}
	}
}

func (f pkgFrameBody) AppendBody(b []byte) []byte {
	if f.Num > 0 {
		b = field.AppendTag(b, field.Value, 127)
		b = field.AppendValue(b, f.Num)
	}

	return f.Msg.appendFields(b)
}

func (f *pkgFrameBody) ParseFields(r *field.Reader) error {
	for {
		tag, err := r.ReadTag()
		if err == io.EOF {
			return nil
		}

		if err != nil {
			return err
		}

		switch tag.Field() {
		case 127:
			f.Num, err = parseNumField(tag, r)

		// copied from Msg.parseFields

		case 1:
			f.Msg.Topic, err = parseTopicField(tag, r)

		case 2:
			f.Msg.Inbox, err = parseTopicField(tag, r)

		case 3:
			f.Msg.Data, err = parseRunField(tag, r)

		case 4:
			f.Msg.Meta, err = parseRunField(tag, r)

		case 5:
			f.Msg.Deadline, err = parseTimeField(tag, r)

		default:
			err = r.Discard(tag)
		}

		if err != nil {
			return fmt.Errorf("parse pkg frame field %d: %v", tag.Field(), err)
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

// just casts
func parseIntField(t field.Tag, r *field.Reader) (int, error) {
	v, err := parseNumField(t, r)
	if err != nil {
		return 0, err
	}
	return int(v), nil
}

// just casts
func parseSelFlagsField(t field.Tag, r *field.Reader) (SelFlags, error) {
	v, err := parseNumField(t, r)
	if err != nil {
		return 0, err
	}
	return SelFlags(v), nil
}

func parseNumField(t field.Tag, r *field.Reader) (uint64, error) {
	if t.Type() != field.Value {
		return 0, errFieldType
	}
	return r.ReadValue()
}

func parseGroupField(t field.Tag, r *field.Reader) (DeliveryGroup, error) {
	b, err := parseRunField(t, r)
	if err != nil {
		return DeliveryGroup{}, err
	}
	return Group(b), nil
}

func parseRunField(t field.Tag, r *field.Reader) ([]byte, error) {
	if t.Type() != field.Run {
		return nil, errFieldType
	}
	return r.ReadRun()
}

var errFieldType = errors.New("invalid type")
