package yat_test

import (
	"encoding/json"
	"math"
	"strings"
	"testing"

	"yat.io/yat"
)

func TestNewPath(t *testing.T) {
	t.Run("panic", func(t *testing.T) {
		defer func() {
			if err := recover(); err == nil {
				t.Fatal("no panic")
			}
		}()

		yat.NewPath("**/path")
	})
}

func TestParsePath(t *testing.T) {
	type testCase struct {
		Path  string
		Valid bool
		Wild  bool
	}

	tt := []testCase{
		// bad
		{Path: strings.Repeat("x", math.MaxUint16+1)},
		{Path: "/"},
		{Path: "//"},
		{Path: "/x"},
		{Path: "x/"},
		{Path: "/x/"},

		// good
		{Path: "", Valid: true},
		{Path: "x", Valid: true},
		{Path: "x/y", Valid: true},
		{Path: "x/y/z", Valid: true},

		// bad wildcards
		{Path: "**/**"},
		{Path: "**/x"},
		{Path: "**x"},
		{Path: "**x**"},
		{Path: "*x"},
		{Path: "x*"},
		{Path: "x**"},
		{Path: "x/**/y"},

		// good wildcards
		{Path: "*", Valid: true, Wild: true},
		{Path: "*/x", Valid: true, Wild: true},
		{Path: "x/*", Valid: true, Wild: true},
		{Path: "*/x/*", Valid: true, Wild: true},
		{Path: "*/*/*", Valid: true, Wild: true},
		{Path: "**", Valid: true, Wild: true},
		{Path: "x/**", Valid: true, Wild: true},
		{Path: "x/y/**", Valid: true, Wild: true},
	}

	for _, tc := range tt {
		t.Run(tc.Path, func(t *testing.T) {
			t.Parallel()

			p, wild, err := yat.ParsePath([]byte(tc.Path))

			switch {
			case err != nil && tc.Valid:
				t.Fatal(err)

			case err == nil && !tc.Valid:
				t.Fatal("no error")

			case tc.Wild && !wild:
				t.Fatal("not wild")

			case !tc.Wild && wild:
				t.Fatal("unexpectedly wild")
			}

			if tc.Valid && p.String() != tc.Path {
				t.Errorf("parsed path %q != %q", p.String(), tc.Path)
			}
		})
	}
}

func TestPath_Clone(t *testing.T) {
	buf := []byte("hello")
	p := must(buf)

	buf[0] = 'H'
	if p.String() != string(buf) {
		t.Fatalf("path doesn't alias its source buffer: %q != %q", p.String(), string(buf))
	}

	c := p.Clone()
	buf[0] = '\''
	if c.Equal(p) {
		t.Fatal("not cloned")
	}
}

func TestPath_IsZero(t *testing.T) {
	zero := yat.Path{}
	nonzero := must("test")

	if !zero.IsZero() {
		t.Fatal("zero is not zero")
	}

	if nonzero.IsZero() {
		t.Fatal("nonzero is zero")
	}
}

func TestPath_Equal(t *testing.T) {
	p1 := must("test")
	p2 := must("test")
	p3 := must("test2")

	if !p1.Equal(p2) {
		t.Fatalf("%v != %v", p1, p2)
	}

	if p1.Equal(p3) {
		t.Fatalf("%v == %v", p1, p3)
	}

	if !(yat.Path{}).Equal(yat.Path{}) {
		t.Fatal("zero != zero")
	}
}

func TestPath_MarshalJSON(t *testing.T) {
	p := must("x/y/z")
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `"x/y/z"` {
		t.Fatalf("json: %q != %q", string(b), `"x/y/z"`)
	}

	var p2 yat.Path
	if err := json.Unmarshal(b, &p2); err != nil {
		t.Fatal(err)
	}

	if !p.Equal(p2) {
		t.Fatalf("%v != %v", p, p2)
	}
}

func TestPath_UnmarshalJSON(t *testing.T) {
	tcs := []struct {
		Name string
		JSON string
	}{
		{"number", `0`},
		{"array", `[]`},
		{"object", `{}`},
		{"bad-string", `"x/y/z`},
		{"bad-path", `"x/**/z"`},
	}

	for _, tc := range tcs {
		t.Run(tc.Name, func(t *testing.T) {
			var p yat.Path
			err := json.Unmarshal([]byte(tc.JSON), &p)
			if err == nil {
				t.Fatal("no error")
			}
		})
	}
}

func must[T ~[]byte | ~string](v T) yat.Path {
	top, _, err := yat.ParsePath([]byte(v))
	if err != nil {
		panic(err)
	}
	return top
}
