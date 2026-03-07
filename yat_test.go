package yat_test

import (
	"strings"
	"testing"

	"yat.io/yat"
)

func TestNewGroup(t *testing.T) {
	const name = "name"
	g := yat.NewGroup(name)
	g1 := yat.NewGroup(name)
	o := yat.NewGroup("other")

	if got, want := g.String(), name; got != want {
		t.Errorf("%q != %q", got, want)
	}

	if g1 != g {
		t.Errorf("%#v != %#v", g1, g)
	}
	if o == g {
		t.Errorf("%#v == %#v", o, g)
	}

	if empty, zero := yat.NewGroup(""), (yat.Group{}); empty != zero {
		t.Errorf("%#v != %#v", empty, zero)
	}

	if s := yat.NewGroup("").String(); s != "" {
		t.Errorf("empty group string %q != %q", s, "")
	}

	defer func() {
		if recover() == nil {
			t.Fatal("no panic")
		}
	}()

	yat.NewGroup("x" + strings.Repeat("x", yat.MaxGroupLen))
}
