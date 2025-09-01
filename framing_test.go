package yat

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/yat/yat/field"
	"github.com/yat/yat/topic"
)

func TestMsgRoundtrip(t *testing.T) {
	mm := []Msg{
		{},
		{Topic: topic.New("topic")},
		{Inbox: topic.New("inbox")},
		{Data: []byte("data")},
		{Meta: []byte("meta")},
		{Deadline: time.Now()},

		{
			Topic:    topic.New("topic"),
			Inbox:    topic.New("inbox"),
			Data:     []byte("data"),
			Meta:     []byte("meta"),
			Deadline: time.Now(),
		},
	}

	for i, m := range mm {
		t.Run(fmt.Sprintf("mm[%d]", i), func(t *testing.T) {
			b := m.appendFields(nil)

			var got Msg
			if err := got.parseFields(field.NewReader(b)); err != nil {
				t.Fatal(err)
			}

			if diff := cmp.Diff(m, got); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestSelRoundtrip(t *testing.T) {
	ss := []Sel{
		{},
		{Topic: topic.New("topic")},
		{Limit: 111},
		{Group: Group("group")},
		{Flags: DATA | INBOX},

		{
			Topic: topic.New("topic"),
			Limit: 1,
			Group: Group("group"),
			Flags: DATA,
		},
	}

	for i, s := range ss {
		t.Run(fmt.Sprintf("ss[%d]", i), func(t *testing.T) {
			b := s.appendFields(nil)

			var got Sel
			if err := got.parseFields(field.NewReader(b)); err != nil {
				t.Fatal(err)
			}

			if diff := cmp.Diff(s, got); diff != "" {
				t.Error(diff)
			}
		})
	}
}
