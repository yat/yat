package topic

import (
	"bytes"
	"iter"
	"slices"
)

//go:generate sh -c "ragel -Z -G2 -o path.rl.go path.rl && go fmt path.rl.go > /dev/null"

// Path is a topic path where messages are published.
// Create one by calling [Parse] or [New].
type Path struct {
	buf []byte
}

// New returns a Path aliasing b, which must be well-formed.
func New(b []byte) Path {
	return Path{b}
}

// Bytes returns the path's backing bytes.
// Modifying these bytes is not allowed.
func (p Path) Bytes() []byte {
	return p.buf
}

// String returns the path as a string.
func (p Path) String() string {
	return string(p.buf)
}

// Equal returns true if the paths are the same.
func (p Path) Equal(other Path) bool {
	return bytes.Equal(p.buf, other.buf)
}

// Match returns true if the given path matches the receiver.
// It gives the same answer as [Tree.Matches].
func (p Path) Match(other Path) bool {
	if p.IsZero() || other.IsZero() {
		return false
	}

	if other.Equal(p) {
		return true
	}

	next, stop := iter.Pull(bytes.SplitSeq(other.buf, []byte{'/'}))
	defer stop()

	for want := range bytes.SplitSeq(p.buf, []byte{'/'}) {
		got, ok := next()
		if !ok {
			return false
		}

		switch string(want) {
		case "*":
			continue

		case "**":
			return true

		default:
			if !bytes.Equal(got, want) {
				return false
			}
		}
	}

	_, ok := next()
	return !ok
}

// Clone returns a copy of the path.
func (p Path) Clone() Path {
	return Path{buf: bytes.Clone(p.buf)}
}

// IsZero returns true if the path is empty.
func (p Path) IsZero() bool {
	return len(p.buf) == 0
}

// Len returns the length of the path in bytes.
func (p Path) Len() int {
	return len(p.buf)
}

// MarshalText implements [encoding.TextMarshaler] by returning a copy of the path.
func (p Path) MarshalText() (text []byte, err error) {
	return append([]byte{}, p.buf...), nil
}

// UnmarshalText implements [encoding.TextUnmarshaler] by parsing a copy of the given text.
func (p *Path) UnmarshalText(text []byte) error {
	parsed, _, err := Parse(slices.Clone(text))
	if err != nil {
		return err
	}

	*p = parsed
	return nil
}

// cut splits the path at the first /.
// car and cdr may be zero values.
func (p Path) cut() (car, cdr Path) {
	car.buf, cdr.buf, _ = bytes.Cut(p.buf, []byte{'/'})
	return
}
