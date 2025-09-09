package yat

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestMsgFields(t *testing.T) {
	mm := []Msg{
		{},
		{Topic: Topic("topic")},
		{Inbox: Topic("inbox")},
		{Data: []byte("data")},
		{Meta: []byte("meta")},
		{Deadline: time.Now()},

		{
			Topic:    Topic("topic"),
			Inbox:    Topic("inbox"),
			Data:     []byte("data"),
			Meta:     []byte("meta"),
			Deadline: time.Now(),
		},
	}

	for i, m := range mm {
		t.Run(fmt.Sprintf("mm[%d]", i), func(t *testing.T) {
			b := m.appendFields(nil)

			var got Msg
			if err := got.parseFields(b); err != nil {
				t.Fatal(err)
			}

			if diff := cmp.Diff(m, got); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func Test_msgFrameBodyFields(t *testing.T) {
	f := msgFrameBody{
		Msg: Msg{
			Topic:    Topic("topic"),
			Inbox:    Topic("inbox"),
			Data:     []byte("data"),
			Meta:     []byte("meta"),
			Deadline: time.Now(),
		},
	}

	b := f.AppendBody(nil)

	var got msgFrameBody
	if err := got.ParseFields(b); err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(f, got); diff != "" {
		t.Error(diff)
	}
}

func Test_subFrameBodyFields(t *testing.T) {
	f := subFrameBody{
		Num: 1,
		Sel: Sel{
			Topic: Topic("topic"),
			Limit: 1,
			Group: Group("group"),
		},
		Flags: SubFlagResponder,
	}

	b := f.AppendBody(nil)

	var got subFrameBody
	if err := got.ParseFields(b); err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(f, got); diff != "" {
		t.Error(diff)
	}
}

func Test_unsubFrameBodyFields(t *testing.T) {
	f := unsubFrameBody{
		Num: 1,
	}

	b := f.AppendBody(nil)

	var got unsubFrameBody
	if err := got.ParseFields(b); err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(f, got); diff != "" {
		t.Error(diff)
	}
}

func Test_pkgFrameBodyFields(t *testing.T) {
	f := pkgFrameBody{
		Num: 1,
		Msg: Msg{
			Topic:    Topic("topic"),
			Inbox:    Topic("inbox"),
			Data:     []byte("data"),
			Meta:     []byte("meta"),
			Deadline: time.Now(),
		},
	}

	b := f.AppendBody(nil)

	var got pkgFrameBody
	if err := got.ParseFields(b); err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(f, got); diff != "" {
		t.Error(diff)
	}
}
