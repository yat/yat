package topic_test

import (
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/yat/yat/topic"
)

func TestParse(t *testing.T) {
	type testCase struct {
		Topic string
		Valid bool
		Wild  bool
	}

	tt := []testCase{
		// bad
		{Topic: strings.Repeat("x", math.MaxUint16+1)},
		{Topic: "/"},
		{Topic: "//"},
		{Topic: "/x"},
		{Topic: "x/"},
		{Topic: "/x/"},

		// good
		{Topic: "", Valid: true},
		{Topic: "x", Valid: true},
		{Topic: "x/y", Valid: true},
		{Topic: "x/y/z", Valid: true},

		// bad wildcards
		{Topic: "**/**"},
		{Topic: "**/x"},
		{Topic: "**x"},
		{Topic: "**x**"},
		{Topic: "*x"},
		{Topic: "x*"},
		{Topic: "x**"},
		{Topic: "x/**/y"},

		// good wildcards
		{Topic: "*", Valid: true, Wild: true},
		{Topic: "*/x", Valid: true, Wild: true},
		{Topic: "x/*", Valid: true, Wild: true},
		{Topic: "*/x/*", Valid: true, Wild: true},
		{Topic: "*/*/*", Valid: true, Wild: true},
		{Topic: "**", Valid: true, Wild: true},
		{Topic: "x/**", Valid: true, Wild: true},
		{Topic: "x/y/**", Valid: true, Wild: true},
	}

	for _, tc := range tt {
		t.Run(tc.Topic, func(t *testing.T) {
			t.Parallel()

			p, wild, err := topic.Parse(tc.Topic)

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

			if tc.Valid && p.String() != tc.Topic {
				t.Errorf("parsed path %q != %q", p.String(), tc.Topic)
			}
		})
	}
}

func must[T ~[]byte | ~string](v T) topic.Path {
	top, _, err := topic.Parse(v)
	if err != nil {
		panic(err)
	}
	return top
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

	if !(topic.Path{}).Equal(topic.Path{}) {
		t.Fatal("zero != zero")
	}
}

func TestPath_IsZero(t *testing.T) {
	zero := topic.Path{}
	nonzero := must("test")

	if !zero.IsZero() {
		t.Fatal("zero is not zero")
	}

	if nonzero.IsZero() {
		t.Fatal("nonzero is zero")
	}
}

func TestPath_Match(t *testing.T) {
	for _, tc := range matchTestCases {
		pat := must(tc.Pat)
		for _, ok := range tc.OK {
			if !pat.Match(must(ok)) {
				t.Errorf("pattern %q doesn't match %q", tc.Pat, ok)
			}
		}

		for _, no := range tc.No {
			if pat.Match(must(no)) {
				t.Errorf("pattern %q unexepectedly matches %q", tc.Pat, no)
			}
		}
	}

	t.Run("zero values", func(t *testing.T) {
		if (topic.Path{}).Match(topic.Path{}) {
			t.Fatal("unexpected match")
		}
	})
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

	var p2 topic.Path
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
		{"bad-topic", `"x/**/z"`},
	}

	for _, tc := range tcs {
		t.Run(tc.Name, func(t *testing.T) {
			var p topic.Path
			err := json.Unmarshal([]byte(tc.JSON), &p)
			if err == nil {
				t.Fatal("no error")
			}
		})
	}
}

type matchTestCase struct {
	Pat string
	OK  []string
	No  []string
}

var matchTestCases = []matchTestCase{
	{Pat: "a", OK: []string{"a"}, No: []string{"b"}},
	{Pat: "a/b", OK: []string{"a/b"}, No: []string{"a", "a/c", "a/b/c"}},
	{Pat: "*", OK: []string{"a", "b"}, No: []string{"a/b", "a/b/c"}},
	{Pat: "a/*", OK: []string{"a/a", "a/b"}, No: []string{"b/a", "a/b/c"}},
	{Pat: "*/a", OK: []string{"a/a", "b/a"}, No: []string{"a/b", "a/a/c"}},
	{Pat: "**", OK: []string{"a", "b", "a/b"}},
	{Pat: "a/**", OK: []string{"a/a", "a/b", "a/b/c"}, No: []string{"b/a", "b", "a"}},
}
