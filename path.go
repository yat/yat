package yat

import "bytes"

//go:generate sh -c "ragel -Z -G2 -o path.rl.go path.rl && go fmt path.rl.go > /dev/null"

type Path struct {
	data []byte
}

// NewPath copies the given string into a new path.
// If the string can't be parsed, NewPath panics.
func NewPath(str string) Path {
	path, _, err := parsePath(str)
	if err != nil {
		panic(err)
	}

	return path
}

// ParsePath parses a path from a raw value.
// If the value is a byte slice, the returned path aliases the slice.
// ParsePath returns an error if the path is invalid.
// If the path contains a * or ** segment, ParsePath returns wild=true.
func ParsePath(raw []byte) (parsed Path, wild bool, err error) {
	return parsePath(raw)
}

// Clone returns a copy of the path.
func (p Path) Clone() Path {
	return Path{bytes.Clone(p.data)}
}

// String returns the path as a string.
func (p Path) String() string {
	return string(p.data)
}

// IsZero returns true if the path is empty.
func (p Path) IsZero() bool {
	return len(p.data) == 0
}

// Equal returns true if the paths are the same.
func (p Path) Equal(other Path) bool {
	return bytes.Equal(p.data, other.data)
}

func (p Path) MarshalText() (text []byte, err error) {
	return bytes.Clone(p.data), nil
}

func (p *Path) UnmarshalText(text []byte) error {
	pp, _, err := ParsePath(bytes.Clone(text))
	if err != nil {
		return err
	}

	*p = pp
	return nil
}

// cut splits the path at the first /.
// car and cdr may be zero values.
func (p Path) cut() (car, cdr Path) {
	car.data, cdr.data, _ = bytes.Cut(p.data, []byte{'/'})
	return
}
