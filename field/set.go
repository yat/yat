// Package field defines and implements a binary encoding for field sets.
// The encoding is similar to the Protocol Buffers wire format, but much more limited.
// The encoding is not general-purpose: It was designed to be used in the Yat network protocol,
// where a handwritten codec is a pain but efficiency and careful memory allocation are required.
// Field sets are designed for structs with a small number of fields containing unsigned integers
// and byte slices. Repeated fields and nested structs are not supported.
//
// A field set is a run of bytes containing zero or more encoded fields.
//
// A field is a 1 byte tag followed by an encoded value.
// The MSB of the tag is the field type, Value (0) or Run (1).
// The least significant 7 bits of the tag are the field number, 0-127.
//
// # Types
//
//   - Values hold a uint64 encoded as a 1-9 byte nv.
//     For encoding details, see the internal/nv package.
//   - Runs hold a run of bytes encoded as an nv len followed by len bytes.
//
// # Codec
//
// Fields may appear in any order.
// Duplicate fields may appear.
//
// Fields with zero values and runs of 0 bytes should not be encoded.
// When decoding, fields with reserved (0) or unknown numbers should be discarded.
// Two errors can occur during decoding: A short field or a Num overflow.
//
// # Limitations
//
// - Structs with field counts exceeding the valid field number range (1-127) can't be encoded.
package field

import (
	"errors"
	"fmt"
	"io"

	"yat.io/yat/nv"
)

type Set []byte

// Tag is the first byte of an encoded field.
// It contains the field's type, cardinality, and number.
type Tag byte

const (
	typeBit = 0b10000000
	numBits = 0b01111111
)

// Type is the type of a field, [Value] or [Run].
type Type byte

const (
	Value = Type(0)
	Run   = Type(typeBit)
)

const (
	MaxTagNum = 127
)

var ErrShort = errors.New("short field")
var ErrOverflow = errors.New("value overflows 64 bits")

func (s Set) AppendValueField(num int, value uint64) Set {
	return nv.Append(s.appendTag(Value, num), value)
}

func (s Set) AppendRunField(num int, run []byte) Set {
	return append(nv.Append(s.appendTag(Run, num), uint64(len(run))), run...)
}

func (s Set) appendTag(typ Type, field int) Set {
	return append(s, byte(typ)|byte(field&numBits))
}

func (s Set) ReadTag() (Set, Tag, error) {
	if len(s) == 0 {
		return nil, 0, io.EOF
	}

	tag := Tag(s[0])
	s = s[1:]

	return s, tag, nil
}

func (s Set) ReadValue() (Set, uint64, error) {
	v, n := nv.Parse(s)
	if n == 0 {
		return nil, 0, ErrShort
	}

	if n < 0 {
		return nil, 0, ErrOverflow
	}

	s = s[n:]

	return s, v, nil
}

func (s Set) ReadRun() (Set, []byte, error) {
	s, rlen, err := s.ReadValue()
	if err != nil {
		return nil, nil, err
	}

	if uint64(len(s)) < rlen {
		return nil, nil, ErrShort
	}

	run := s[:rlen]
	s = s[rlen:]

	return s, run, nil
}

func (s Set) Discard(t Tag) (Set, error) {
	s, v, err := s.ReadValue()
	if err != nil {
		return nil, err
	}

	if t.Type() == Run {
		if uint64(len(s)) < v {
			return nil, ErrShort
		}
		s = s[v:]
	}

	return s, nil
}

// Type returns the field type.
func (t Tag) Type() Type {
	return Type(t & typeBit)
}

// Num returns the field number, 0-127.
func (t Tag) Field() int {
	return int(t & numBits)
}

// String returns the name of the type, "Value" or "Run".
// If the value is invalid String returns "Type(value)".
func (t Type) String() string {
	switch t {
	case Value:
		return "Value"
	case Run:
		return "Run"
	default:
		return fmt.Sprintf("Type(%d)", t)
	}
}
