package yat_test

import (
	"fmt"
	"testing"
	"time"

	"yat.io/yat"
)

func TestMsg_IsExpired(t *testing.T) {
	tcs := []struct {
		Msg     yat.Msg
		Expired bool
	}{
		{yat.Msg{}, false},
		{yat.Msg{Deadline: time.Now().Add(1 * time.Second)}, false},
		{yat.Msg{Deadline: time.Now().Add(-1 * time.Second)}, true},
	}

	for i, tc := range tcs {
		t.Run(fmt.Sprintf("tc[%d]", i), func(t *testing.T) {
			if tc.Msg.IsExpired() != tc.Expired {
				t.Errorf("IsExpired != %v", tc.Expired)
			}
		})
	}
}

func TestTopic(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Error("no panic")
			}
		}()

		yat.Topic("/")
	})
}

func TestGroup(t *testing.T) {
	t.Run("zero", func(t *testing.T) {
		if got, want := yat.Group(""), (yat.DeliveryGroup{}); got != want {
			t.Errorf("%v != %v", got, want)
		}
	})

	t.Run("intern", func(t *testing.T) {
		if got, want := yat.Group("x"), yat.Group("x"); got != want {
			t.Errorf("group x: %v != %v", got, want)
		}
	})
}

func TestDeliveryGroup_IsZero(t *testing.T) {

}

func TestDeliveryGroup_Equal(t *testing.T) {
	tcs := []struct{ A, B yat.DeliveryGroup }{
		{yat.Group("a"), yat.Group("a")},
		{yat.Group("a"), yat.Group("b")},
		{yat.Group("a"), yat.DeliveryGroup{}},
		{yat.DeliveryGroup{}, yat.DeliveryGroup{}},
	}

	for _, tc := range tcs {
		if tc.A.Equal(tc.B) != (tc.A == tc.B) {
			t.Errorf("A %v Equal B %v != %v", tc.A, tc.B, tc.A == tc.B)
		}

		if tc.B.Equal(tc.A) != (tc.A == tc.B) {
			t.Errorf("B %v Equal A %v != %v", tc.B, tc.A, tc.A == tc.B)
		}
	}
}

func TestDeliveryGroup_String(t *testing.T) {
	names := []string{
		"",
		"name",
	}

	for _, name := range names {
		g := yat.Group(name)
		if got, want := g.String(), name; got != want {
			t.Errorf("%q != %q", got, want)
		}
	}
}

func TestSubFlags_String(t *testing.T) {
	tcs := map[yat.SubFlags]string{
		yat.SubFlagResponder: "Responder",
		99:                   "SubFlags(99)",
	}

	for flags, want := range tcs {
		if got := flags.String(); got != want {
			t.Errorf("%0b: %q != %q", flags, got, want)
		}
	}
}
