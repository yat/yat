package yat_test

import (
	"encoding/json"
	"strings"
	"testing"

	"yat.io/yat"
)

func TestNewPath(t *testing.T) {
	defer func() {
		if err := recover(); err == nil {
			t.Fatal("no panic")
		}
	}()

	// ** must be a suffix
	yat.NewPath("**/path")
}

func TestParsePath(t *testing.T) {
	type testCase struct {
		Path  string
		Valid bool
	}

	tcs := []testCase{
		// bad
		{Path: ""},
		{Path: strings.Repeat("x", yat.MaxPathLen+1)},
		{Path: "/"},
		{Path: "//"},
		{Path: "/x"},
		{Path: "x/"},
		{Path: "/x/"},

		// good
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
		{Path: "*", Valid: true},
		{Path: "*/x", Valid: true},
		{Path: "x/*", Valid: true},
		{Path: "*/x/*", Valid: true},
		{Path: "*/*/*", Valid: true},
		{Path: "**", Valid: true},
		{Path: "x/**", Valid: true},
		{Path: "x/y/**", Valid: true},
	}

	for _, tc := range tcs {
		t.Run(tc.Path, func(t *testing.T) {
			t.Parallel()

			p, err := yat.ParsePath([]byte(tc.Path))

			switch {
			case err != nil && tc.Valid:
				t.Fatal(err)

			case err == nil && !tc.Valid:
				t.Fatal("no error")
			}

			if tc.Valid && p.String() != tc.Path {
				t.Errorf("parsed path %q != %q", p.String(), tc.Path)
			}
		})
	}
}

func TestPath_IsZero(t *testing.T) {
	zero := yat.Path{}
	nonzero := yat.NewPath("test")

	if !zero.IsZero() {
		t.Fatal("zero is not zero")
	}

	if nonzero.IsZero() {
		t.Fatal("nonzero is zero")
	}
}

func TestPath_Equal(t *testing.T) {
	p1 := yat.NewPath("test")
	p2 := yat.NewPath("test")
	p3 := yat.NewPath("test2")

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

func TestPath_Match(t *testing.T) {
	if (yat.Path{}).Match(yat.Path{}) {
		t.Error("zero paths shouldn't match anything")
	}
}

func TestPath_MarshalJSON(t *testing.T) {
	p := yat.NewPath("x/y/z")
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
