package yat

import "unique"

// Group identifies a route group.
type Group struct {
	g unique.Handle[string]
}

// MaxGroupLen is the maximum length of a route group name.
const MaxGroupLen = 1 << 10

// NewGroup returns a route group with the given name.
// If the name is longer than [MaxGroupLen], NewGroup panics.
// Groups with the same name are identical.
// The name of the zero group is "".
func NewGroup(name string) Group {
	if name == "" {
		return Group{}
	}

	if len(name) > MaxGroupLen {
		panic(errLongGroup)
	}

	return Group{unique.Make(name)}
}

// String returns the group name.
func (g Group) String() string {
	switch g {
	case Group{}:
		return ""

	default:
		return g.g.Value()
	}
}

// IsZero returns true for the zero group.
func (g Group) IsZero() bool {
	return g == Group{}
}
