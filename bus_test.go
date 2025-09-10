package yat_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"yat.io/yat"
)

var _ yat.Publisher = (*yat.Bus)(nil)
var _ yat.Subscriber = (*yat.Bus)(nil)

// var _ yat.Caller = (*yat.Bus)(nil)

func TestBus(t *testing.T) {
	testPublishSubscriber(t, func() publishSubscriber { return &yat.Bus{} })
}

type publishSubscriber interface {
	yat.Publisher
	yat.Subscriber
}

func testPublishSubscriber(t *testing.T, new func() publishSubscriber) {
	t.Run("self", func(t *testing.T) {
		ps := new()

		sel := yat.Sel{
			Topic: yat.Topic("hello"),
		}

		mC := make(chan yat.Msg, 1)
		_, err := ps.Subscribe(sel, 0, func(m yat.Msg) { mC <- m.Clone() })
		if err != nil {
			t.Fatal(err)
		}

		want := yat.Msg{
			Topic: sel.Topic,
			Data:  []byte("hi"),
		}

		if err := ps.Publish(want); err != nil {
			t.Fatal(err)
		}

		got := <-mC
		if diff := cmp.Diff(want, got); diff != "" {
			t.Error(diff)
		}
	})
}
