package yat

import (
	"errors"
	"fmt"
	"io"
	"time"

	"yat.io/yat/field"
	"yat.io/yat/nv"
	"yat.io/yat/topic"
)

type msgFrameBody struct {
	Msg Msg
}

type subFrameBody struct {
	Num   uint64
	Sel   Sel
	Flags SubFlags
}

type unsubFrameBody struct {
	Num uint64
}

type pkgFrameBody struct {
	Num uint64
	Msg Msg
}

const (
	fMSG   = 2
	fSUB   = 3
	fUNSUB = 4
	fPKG   = 128
)

// The parse methods in this file don't clear self before parsing.

func (f msgFrameBody) AppendBody(b []byte) []byte {
	return f.Msg.appendFields(b)
}

func (f *msgFrameBody) ParseFields(s field.Set) error {
	return f.Msg.parseFields(s)
}

func (f subFrameBody) AppendBody(b []byte) []byte {
	s := field.Set(b)
	if f.Num > 0 {
		s = s.AppendValField(1, f.Num)
	}

	if !f.Sel.Topic.IsZero() {
		s = s.AppendRunField(2, f.Sel.Topic.Bytes())
	}

	if f.Sel.Limit > 0 {
		s = s.AppendValField(3, uint64(f.Sel.Limit))
	}

	if !f.Sel.Group.IsZero() {
		s = s.AppendRunField(4, []byte(f.Sel.Group.String()))
	}

	if f.Flags != 0 {
		s = s.AppendValField(5, uint64(f.Flags))
	}

	return s
}

func (f *subFrameBody) ParseFields(s field.Set) error {
	var tag field.Tag
	var err error

	for {
		s, tag, err = s.ReadTag()
		if err == io.EOF {
			return nil
		}

		if err != nil {
			return err
		}

		switch tag.Field() {
		case 1:
			s, f.Num, err = readValueField(tag, s)

		case 2:
			s, f.Sel.Topic, err = readTopicField(tag, s)

		case 3:
			s, f.Sel.Limit, err = readIntField(tag, s)

		case 4:
			s, f.Sel.Group, err = readGroupField(tag, s)

		case 5:
			s, f.Flags, err = readSubFlagsField(tag, s)

		default:
			s, err = s.Discard(tag)
		}

		if err != nil {
			return fmt.Errorf("parse sub frame body field %d: %v", tag.Field(), err)
		}
	}
}

func (f unsubFrameBody) AppendBody(b []byte) []byte {
	s := field.Set(b)
	if f.Num > 0 {
		s = s.AppendValField(1, f.Num)
	}
	return s
}

func (f *unsubFrameBody) ParseFields(s field.Set) error {
	var tag field.Tag
	var err error

	for {
		s, tag, err = s.ReadTag()
		if err == io.EOF {
			return nil
		}

		if err != nil {
			return err
		}

		switch tag.Field() {
		case 1:
			s, f.Num, err = readValueField(tag, s)

		default:
			s, err = s.Discard(tag)
		}

		if err != nil {
			return fmt.Errorf("parse unsub frame body field %d: %v", tag.Field(), err)
		}
	}
}

func (f pkgFrameBody) AppendBody(b []byte) []byte {
	return f.Msg.appendFields(nv.Append(b, f.Num))
}

func (f *pkgFrameBody) ParseFields(s field.Set) error {
	num, n := nv.Parse(s)
	if n <= 0 {
		panic("FIX: malformed pkg frame body")
	}

	f.Num = num
	return f.Msg.parseFields(s[n:])
}

func (m Msg) appendFields(s field.Set) []byte {
	if m.fields != nil {
		return append(s, *m.fields...)
	}

	if !m.Topic.IsZero() {
		s = s.AppendRunField(1, m.Topic.Bytes())
	}

	if !m.Inbox.IsZero() {
		s = s.AppendRunField(2, m.Inbox.Bytes())
	}

	if len(m.Data) > 0 {
		s = s.AppendRunField(3, m.Data)
	}

	if len(m.Meta) > 0 {
		s = s.AppendRunField(4, m.Meta)
	}

	if !m.Deadline.IsZero() {
		s = s.AppendValField(5, uint64(m.Deadline.UnixNano()))
	}

	return s
}

func (m *Msg) parseFields(s field.Set) error {

	var tag field.Tag
	var err error

	for {
		s, tag, err = s.ReadTag()
		if err == io.EOF {
			return nil
		}

		if err != nil {
			return err
		}

		switch tag.Field() {

		case 1:
			s, m.Topic, err = readTopicField(tag, s)

		case 2:
			s, m.Inbox, err = readTopicField(tag, s)

		case 3:
			s, m.Data, err = readRunField(tag, s)

		case 4:
			s, m.Meta, err = readRunField(tag, s)

		case 5:
			s, m.Deadline, err = readTimeField(tag, s)

		default:
			s, err = s.Discard(tag)
		}

		if err != nil {
			return fmt.Errorf("parse message field %d: %v", tag.Field(), err)
		}
	}
}

// just casts
func readSubFlagsField(t field.Tag, s field.Set) (field.Set, SubFlags, error) {
	s, v, err := readValueField(t, s)
	if err != nil {
		return nil, 0, err
	}
	return s, SubFlags(v), nil
}

func readTopicField(t field.Tag, s field.Set) (rest field.Set, parsed topic.Path, err error) {
	rest, raw, err := readRunField(t, s)
	if err != nil {
		return
	}

	parsed, _, err = topic.Parse(raw)
	if err != nil {
		rest = nil
	}

	return
}

func readTimeField(t field.Tag, s field.Set) (rest field.Set, parsed time.Time, err error) {
	rest, ns, err := readValueField(t, s)
	if err != nil {
		return
	}
	parsed = time.Unix(int64(ns/uint64(time.Second)), int64(ns%uint64(time.Second)))
	return
}

// just casts
func readIntField(t field.Tag, s field.Set) (field.Set, int, error) {
	s, v, err := readValueField(t, s)
	if err != nil {
		return nil, 0, err
	}
	return s, int(v), nil
}

func readGroupField(t field.Tag, s field.Set) (field.Set, DeliveryGroup, error) {
	s, b, err := readRunField(t, s)
	if err != nil {
		return nil, DeliveryGroup{}, err
	}
	return s, Group(b), nil
}

func readValueField(t field.Tag, s field.Set) (field.Set, uint64, error) {
	if t.Type() != field.Val {
		return nil, 0, errFieldType
	}
	return s.ReadVal()
}

func readRunField(t field.Tag, s field.Set) (field.Set, []byte, error) {
	if t.Type() != field.Run {
		return nil, nil, errFieldType
	}
	return s.ReadRun()
}

var errFieldType = errors.New("invalid type")
