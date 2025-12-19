package yat

import (
	"testing"
)

// TestPathMatch makes sure path.Match and rnode.Match give the same answer.
func TestPathMatch(t *testing.T) {
	tcs := []struct {
		Name    string
		Pattern string
		Path    string
	}{
		{"literal-match", "x", "x"},
		{"literal-miss", "x", "y"},
		{"single-wildcard", "*", "anything"},
		{"single-wildcard-miss", "*", "a/b"},
		{"prefix-wildcard", "x/*", "x/y"},
		{"prefix-wildcard-miss", "x/*", "x/y/z"},
		{"infix-wildcards", "*/*", "a/b"},
		{"infix-wildcards-miss", "*/*", "a"},
		{"double-star-root", "**", "x/y/z"},
		{"double-star-prefix", "x/**", "x/y/z"},
		{"double-star-prefix-min", "x/**", "x/y"},
		{"double-star-prefix-miss", "x/**", "x"},
		{"mixed-double-star", "*/**", "a/b/c"},
		{"mixed-double-star-miss", "*/**", "a"},
		{"empty", "x", ""},
	}

	for _, tc := range tcs {
		t.Run(tc.Name, func(t *testing.T) {
			pat := NewPath(tc.Pattern)
			path := NewPath(tc.Path)

			pres := pat.Match(path)
			rres := rmatch(pat, path)

			if pres != rres {
				t.Errorf("match(%q, %q): path.Match=%v, rmatch=%v", path, path, pres, rres)
			}
		})
	}
}

func rmatch(pattern, path Path) bool {
	var root rnode
	root.Ins(&rsub{Sel: Sel{Path: pattern}})
	return len(root.Match(path)) > 0
}
