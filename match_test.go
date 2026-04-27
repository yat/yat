//go:build !human

// These tests compare Path.Match and rnode.Match to keep routing and auth consistent.
// The file is in package yat so rnode is visible, but referencing internal symbols
// other than rnode.Match is not allowed.

package yat

import (
	"slices"
	"testing"
)

var matchTests = []struct {
	name    string
	pattern string
	path    string
	want    bool
}{
	// Zero values never match.
	{name: "zero_pattern_zero_path", pattern: "", path: "", want: false},
	{name: "zero_pattern_nonzero_path", pattern: "", path: "alpha", want: false},
	{name: "nonzero_pattern_zero_path", pattern: "alpha", path: "", want: false},

	// Exact paths.
	{name: "exact_single", pattern: "alpha", path: "alpha", want: true},
	{name: "exact_single_miss", pattern: "alpha", path: "beta", want: false},
	{name: "exact_prefix_is_not_match", pattern: "alpha", path: "alpha/beta", want: false},
	{name: "exact_needs_full_path", pattern: "alpha/beta", path: "alpha", want: false},
	{name: "exact_deep", pattern: "alpha/beta/gamma", path: "alpha/beta/gamma", want: true},
	{name: "exact_deep_miss", pattern: "alpha/beta/gamma", path: "alpha/beta/delta", want: false},

	// Single-element wildcards.
	{name: "root_star_matches_one_element", pattern: "*", path: "alpha", want: true},
	{name: "root_star_does_not_match_two_elements", pattern: "*", path: "alpha/beta", want: false},
	{name: "root_star_matches_star_path_once", pattern: "*", path: "*", want: true},
	{name: "root_star_does_not_match_suffix_path", pattern: "*", path: "**", want: false},
	{name: "prefix_star_matches_child", pattern: "alpha/*", path: "alpha/beta", want: true},
	{name: "prefix_star_does_not_match_prefix", pattern: "alpha/*", path: "alpha", want: false},
	{name: "prefix_star_does_not_match_deeper_path", pattern: "alpha/*", path: "alpha/beta/gamma", want: false},
	{name: "prefix_star_matches_same_selector_once", pattern: "alpha/*", path: "alpha/*", want: true},
	{name: "prefix_star_does_not_match_suffix_selector", pattern: "alpha/*", path: "alpha/**", want: false},

	// Suffix wildcards. ** means one or more remaining elements.
	{name: "root_suffix_matches_one_element", pattern: "**", path: "alpha", want: true},
	{name: "root_suffix_matches_deep_path", pattern: "**", path: "alpha/beta/gamma", want: true},
	{name: "root_suffix_matches_star_selector", pattern: "**", path: "*", want: true},
	{name: "root_suffix_matches_same_selector_once", pattern: "**", path: "**", want: true},
	{name: "prefix_suffix_does_not_match_prefix", pattern: "alpha/**", path: "alpha", want: false},
	{name: "prefix_suffix_matches_child", pattern: "alpha/**", path: "alpha/beta", want: true},
	{name: "prefix_suffix_matches_deep_path", pattern: "alpha/**", path: "alpha/beta/gamma", want: true},
	{name: "prefix_suffix_matches_deeper_suffix_selector", pattern: "alpha/**", path: "alpha/beta/**", want: true},
	{name: "prefix_suffix_matches_star_selector", pattern: "alpha/**", path: "alpha/*", want: true},
	{name: "prefix_suffix_matches_same_selector_once", pattern: "alpha/**", path: "alpha/**", want: true},

	// Wildcards in the middle of the path.
	{name: "middle_star_matches", pattern: "alpha/*/gamma", path: "alpha/beta/gamma", want: true},
	{name: "middle_star_does_not_match_short_path", pattern: "alpha/*/gamma", path: "alpha/beta", want: false},
	{name: "middle_star_does_not_match_deeper_path", pattern: "alpha/*/gamma", path: "alpha/beta/gamma/delta", want: false},
	{name: "middle_star_does_not_match_different_suffix", pattern: "alpha/*/gamma", path: "alpha/beta/delta", want: false},
	{name: "root_middle_star_matches", pattern: "*/beta", path: "alpha/beta", want: true},
	{name: "root_middle_star_does_not_match_deeper_path", pattern: "*/beta", path: "alpha/beta/gamma", want: false},
	{name: "two_stars_match_two_elements", pattern: "*/*", path: "alpha/beta", want: true},
	{name: "two_stars_do_not_match_one_element", pattern: "*/*", path: "alpha", want: false},
	{name: "two_stars_do_not_match_three_elements", pattern: "*/*", path: "alpha/beta/gamma", want: false},
	{name: "two_stars_match_same_selector_once", pattern: "*/*", path: "*/*", want: true},
	{name: "two_stars_do_not_match_star_suffix_selector", pattern: "*/*", path: "*/**", want: false},

	// Suffix wildcards after a single-element wildcard.
	{name: "star_suffix_does_not_match_one_element", pattern: "*/**", path: "alpha", want: false},
	{name: "star_suffix_matches_two_elements", pattern: "*/**", path: "alpha/beta", want: true},
	{name: "star_suffix_matches_deep_path", pattern: "*/**", path: "alpha/beta/gamma", want: true},
	{name: "star_suffix_matches_two_star_selector_once", pattern: "*/**", path: "*/*", want: true},
	{name: "star_suffix_matches_named_star_selector_once", pattern: "*/**", path: "*/beta", want: true},
	{name: "star_suffix_matches_same_selector_once", pattern: "*/**", path: "*/**", want: true},
	{name: "fixed_star_suffix_does_not_match_two_elements", pattern: "alpha/*/**", path: "alpha/beta", want: false},
	{name: "fixed_star_suffix_matches_deeper_path", pattern: "alpha/*/**", path: "alpha/beta/gamma", want: true},
	{name: "fixed_star_suffix_matches_same_selector_once", pattern: "alpha/*/**", path: "alpha/*/**", want: true},
	{name: "fixed_star_suffix_does_not_match_prefix_suffix_selector", pattern: "alpha/*/**", path: "alpha/**", want: false},

	// Router postboxes should only match exact postbox paths.
	{name: "postbox_exact_root", pattern: "@reply", path: "@reply", want: true},
	{name: "postbox_exact_child", pattern: "@reply/child", path: "@reply/child", want: true},
	{name: "postbox_root_does_not_match_child", pattern: "@reply", path: "@reply/child", want: false},
	{name: "postbox_child_does_not_match_root", pattern: "@reply/child", path: "@reply", want: false},
	{name: "postbox_root_star_does_not_match_root", pattern: "*", path: "@reply", want: false},
	{name: "postbox_root_suffix_does_not_match_root", pattern: "**", path: "@reply", want: false},
	{name: "postbox_root_suffix_does_not_match_child", pattern: "**", path: "@reply/child", want: false},
	{name: "postbox_prefix_star_does_not_match_child", pattern: "@reply/*", path: "@reply/child", want: false},
	{name: "postbox_prefix_suffix_does_not_match_child", pattern: "@reply/**", path: "@reply/child", want: false},
}

func TestMatch(t *testing.T) {
	for _, tt := range matchTests {
		t.Run(tt.name, func(t *testing.T) {
			pattern := toPath(tt.pattern)
			path := toPath(tt.path)

			if got := pattern.Match(path); got != tt.want {
				t.Errorf("Path.Match(%q, %q) = %v, want %v",
					tt.pattern, tt.path, got, tt.want)
			}

			matched := rnodeMatch(pattern, path)
			if tt.want {
				if !matched {
					t.Errorf("rnode.Match(%q, %q) = false, want true",
						tt.pattern, tt.path)
				}
			} else {
				if matched {
					t.Errorf("rnode.Match(%q, %q) = true, want false",
						tt.pattern, tt.path)
				}
			}
		})
	}
}

func toPath(s string) Path {
	if s == "" {
		return Path{}
	}
	return NewPath(s)
}

func rnodeMatch(pattern Path, path Path) bool {
	var root rnode
	entry := root.Ins(rsub{Sel: Sel{Path: pattern}}, nil)
	return slices.Contains(root.Match(path), entry)
}
