// Package field defines and implements a binary encoding for field sets.
// The encoding is similar to the Protocol Buffers wire format, but much more limited.
// The encoding is not general-purpose: It was designed to be used in the Yat network protocol,
// where a handwritten codec is a pain but efficiency and careful memory allocation are required.
// Field sets are designed for structs with a small number of simple fields,
// mostly unsigned integers and byte slices.
//
// A field set is a run of bytes containing zero or more encoded fields.
//
// A field is a 1 byte tag followed by an encoded value.
// The MSB of the tag is the field type, Num (0) or Run (1).
// The next bit of the tag is the field cardinality, N (0) or One (1).
// The least significant 6 bits of the tag are the field number, 0-63.
//
// # Values
//
//   - Num values hold a uint64 encoded as a 1-9 byte nv.
//     For encoding details, see the internal/nv package.
//   - Run values hold a run of bytes encoded as an nv len followed by len bytes.
//
// # Cardinality
//
// A field contains either a single value (cardinality 1)
// or an array of values prefixed by an nv count (cardinality 0).
//
// # Codec
//
// Fields may appear in any order.
// Duplicate fields may appear.
//
// Only fields with nonzero values should be encoded.
// A field's value is nonzero if it contains a Num > 0 or a Run of > 0 bytes,
// or if the field has a cardinality of N and a count > 0.
// When decoding, fields with reserved (0) or unknown numbers should be discarded.
// Two errors can occur during decoding: A short field or a Num overflow.
//
// # Limitations
//
// - Structs with field counts exceeding the valid field number range (1-63) can't be encoded.
package field

import (
	"fmt"

	"github.com/yat/yat/internal/nv"
)

// Tag is the first byte of an encoded field.
// It contains the field's type, cardinality, and number.
type Tag byte

const (
	typeBit = 0b10000000
	cardBit = 0b01000000
	numBits = 0b00111111
)

// Type is the type of a field, [Num] or [Run].
type Type byte

const (
	Num = Type(0)
	Run = Type(typeBit)
)

// Card is the cardinality of a field, [N] or [One].
type Card byte

const (
	N   = Card(0)       // the field contains 1 or more values
	One = Card(cardBit) // the field contains exactly 1 value
)

const (
	MaxTagNum = 63
)

// AppendTag appends a tag byte to b and returns the extended slice.
// The field number must be in the range 0-63:
// Larger numbers are reduced to their least significant 6 bits.
func AppendTag(b []byte, typ Type, card Card, field int) []byte {
	return append(b, byte(typ)|byte(card)|byte(field&numBits))
}

func AppendRun[T ~[]byte | ~string](b []byte, value T) []byte {
	return append(nv.Append(b, uint64(len(value))), value...)
}

// Type returns the field type.
func (t Tag) Type() Type {
	return Type(t & typeBit)
}

// Card returns the field cardinality.
func (t Tag) Card() Card {
	return Card(t & cardBit)
}

// Num returns the field number, 0-63.
func (t Tag) Field() int {
	return int(t & numBits)
}

// String returns the name of the type, "Num" or "Run".
// If the value is invalid String returns "Type(value)".
func (t Type) String() string {
	switch t {
	case Num:
		return "Num"
	case Run:
		return "Run"
	default:
		return fmt.Sprintf("Type(%d)", t)
	}
}

// String returns a string describing the cardinality, "N" or "One".
// If the value is invalid, String returns "Card(value)".
func (c Card) String() string {
	switch c {
	case N:
		return "N"
	case One:
		return "One"
	default:
		return fmt.Sprintf("Card(%d)", c)
	}
}
