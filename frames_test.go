package yat

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func Test_msgFrameBody(t *testing.T) {
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

func Test_subFrameBody(t *testing.T) {
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

func Test_unsubFrameBody(t *testing.T) {
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

func Test_pkgFrameBody(t *testing.T) {
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
