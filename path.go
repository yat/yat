package yat

import (
	"bytes"
	"slices"
)

//go:generate sh -c "ragel -Z -G2 -o path.rl.go path.rl && go fmt path.rl.go > /dev/null"

type Path struct {
	p []byte
}

// NewPath parses the given string into a new path.
// If the string is not a valid path, NewPath panics.
func NewPath(str string) Path {
	path, _, err := ParsePath(str)
	if err != nil {
		panic(err)
	}

	return path
}

// Match returns true if the given path matches the receiver,
// which may contain * or ** wildcards.
// Zero values never match.
func (p Path) Match(o Path) bool {
	if p.IsZero() || o.IsZero() {
		return false
	}

	// head segments
	var ps, os Path

	for {
		ps, p = p.cut()
		os, o = o.cut()

		if ps.IsZero() {
			return os.IsZero()
		}

		if os.IsZero() {
			return false
		}

		switch ps.String() {
		case "*":
			continue

		case "**":
			return true

		default:
			if !os.Equal(ps) {
				return false
			}
		}
	}
}

// Clone returns a copy of the path.
func (p Path) Clone() Path {
	return Path{bytes.Clone(p.p)}
}

// String returns the path as a string.
func (p Path) String() string {
	return string(p.p)
}

// IsWild returns true if the path contains a * or ** wildcard.
func (p Path) IsWild() bool {
	return slices.Contains(p.p, '*')
}

// IsZero returns true if the path is empty.
func (p Path) IsZero() bool {
	return len(p.p) == 0
}

// Equal returns true if the paths are the same.
func (p Path) Equal(other Path) bool {
	return bytes.Equal(p.p, other.p)
}

func (p Path) MarshalText() (text []byte, err error) {
	return bytes.Clone(p.p), nil
}

func (p *Path) UnmarshalText(text []byte) error {
	parsed, _, err := ParsePath(bytes.Clone(text))
	if err != nil {
		return err
	}

	*p = parsed
	return nil
}

// cut splits the path at the first /.
// car and cdr may be zero values.
func (p Path) cut() (car, cdr Path) {
	car.p, cdr.p, _ = bytes.Cut(p.p, []byte{'/'})
	return
}
