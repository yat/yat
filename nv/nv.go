// Package nv implements a wire encoding for integers.
//
// An nv is 1-65 bytes long, with a range of +- (2^512)-1.
// The [Append], [Put], [Parse], and [Len] functions support uint64 values,
// which are encoded in 1-9 bytes.
//
// The first byte of an nv is tagged. If the most significant bit (b7) is 0,
// the entire value 0-127 is encoded in the remaining 7 bits of the tagged byte.
// If b7 is 1, b6 is a sign flag (1=-) and b0-b5 encode the number-1 of following bytes,
// which contain the little-endian magnitude.
//
// Non-canonical encodings are not allowed.
// Values must be encoded using the smallest possible number of bytes.
package nv

import "math/bits"

const MaxLen64 = 9

// Append appends the encoded value to b and returns the extended slice.
func Append(b []byte, value uint64) []byte {
	if value < 128 {
		return append(b, byte(value))
	}

	nb := (bits.Len64(value) + 7) >> 3
	b = append(b, (1<<7)|byte(nb-1))

	switch nb {
	case 1:
		b = append(b, byte(value))

	case 2:
		b = append(b,
			byte(value),
			byte(value>>8))

	case 3:
		b = append(b,
			byte(value),
			byte(value>>8),
			byte(value>>16))

	case 4:
		b = append(b,
			byte(value),
			byte(value>>8),
			byte(value>>16),
			byte(value>>24))

	case 5:
		b = append(b,
			byte(value),
			byte(value>>8),
			byte(value>>16),
			byte(value>>24),
			byte(value>>32))

	case 6:
		b = append(b,
			byte(value),
			byte(value>>8),
			byte(value>>16),
			byte(value>>24),
			byte(value>>32),
			byte(value>>40))

	case 7:
		b = append(b,
			byte(value),
			byte(value>>8),
			byte(value>>16),
			byte(value>>24),
			byte(value>>32),
			byte(value>>40),
			byte(value>>48))

	case 8:
		b = append(b,
			byte(value),
			byte(value>>8),
			byte(value>>16),
			byte(value>>24),
			byte(value>>32),
			byte(value>>40),
			byte(value>>48),
			byte(value>>56))
	}

	return b
}

// Put encodes the value into b and returns the number of bytes written.
// If the buffer is too small, Put panics.
func Put(b []byte, value uint64) int {
	if value < 128 {
		b[0] = byte(value)
		return 1
	}

	nb := (bits.Len64(value) + 7) >> 3
	b[0] = (1 << 7) | byte(nb-1)

	// for i := range nb {
	// 	b[1+i] = byte(value)
	// 	value >>= 8
	// }

	switch nb {
	case 1:
		b[1] = byte(value)

	case 2:
		b[1] = byte(value)
		b[2] = byte(value >> 8)

	case 3:
		b[1] = byte(value)
		b[2] = byte(value >> 8)
		b[3] = byte(value >> 16)

	case 4:
		b[1] = byte(value)
		b[2] = byte(value >> 8)
		b[3] = byte(value >> 16)
		b[4] = byte(value >> 24)

	case 5:
		b[1] = byte(value)
		b[2] = byte(value >> 8)
		b[3] = byte(value >> 16)
		b[4] = byte(value >> 24)
		b[5] = byte(value >> 32)

	case 6:
		b[1] = byte(value)
		b[2] = byte(value >> 8)
		b[3] = byte(value >> 16)
		b[4] = byte(value >> 24)
		b[5] = byte(value >> 32)
		b[6] = byte(value >> 40)

	case 7:
		b[1] = byte(value)
		b[2] = byte(value >> 8)
		b[3] = byte(value >> 16)
		b[4] = byte(value >> 24)
		b[5] = byte(value >> 32)
		b[6] = byte(value >> 40)
		b[7] = byte(value >> 48)

	case 8:
		b[1] = byte(value)
		b[2] = byte(value >> 8)
		b[3] = byte(value >> 16)
		b[4] = byte(value >> 24)
		b[5] = byte(value >> 32)
		b[6] = byte(value >> 40)
		b[7] = byte(value >> 48)
		b[8] = byte(value >> 56)
	}

	return 1 + nb
}

// Parse decodes a value from b, returning the value and the number of bytes read (> 0).
// If n == 0, the buffer is too small. If n < 0, the encoding is invalid
// or the value overflows uint64 and -n is the number of encoded bytes.
//
// Parse rejects non-canonical encodings:
// A value < 128 must be encoded in 1 byte.
// If a value is encoded in > 1 byte, the last encoded byte must not be 0.
func Parse(b []byte) (value uint64, n int) {
	if len(b) == 0 {
		return 0, 0
	}

	t := b[0]
	if t&(1<<7) == 0 {
		return uint64(t), 1
	}

	nb := int(t&0b111111) + 1

	n = 1 + nb
	if len(b) < n {
		return 0, 0
	}

	// overflows uint64
	if nb > 8 || t&(1<<6) != 0 {
		return 0, -n
	}

	// should've been 1 byte
	if nb == 1 && b[1] < 128 {
		return 0, -n
	}

	// no extra zeroes
	if nb > 1 && b[nb] == 0 {
		return 0, -n
	}

	// for i := range nb {
	// 	value |= uint64(b[1+i]) << (i * 8)
	// }

	switch nb {
	case 1:
		value = uint64(b[1])

	case 2:
		value = uint64(b[1]) |
			uint64(b[2])<<8

	case 3:
		value = uint64(b[1]) |
			uint64(b[2])<<8 |
			uint64(b[3])<<16

	case 4:
		value = uint64(b[1]) |
			uint64(b[2])<<8 |
			uint64(b[3])<<16 |
			uint64(b[4])<<24

	case 5:
		value = uint64(b[1]) |
			uint64(b[2])<<8 |
			uint64(b[3])<<16 |
			uint64(b[4])<<24 |
			uint64(b[5])<<32

	case 6:
		value = uint64(b[1]) |
			uint64(b[2])<<8 |
			uint64(b[3])<<16 |
			uint64(b[4])<<24 |
			uint64(b[5])<<32 |
			uint64(b[6])<<40

	case 7:
		value = uint64(b[1]) |
			uint64(b[2])<<8 |
			uint64(b[3])<<16 |
			uint64(b[4])<<24 |
			uint64(b[5])<<32 |
			uint64(b[6])<<40 |
			uint64(b[7])<<48

	case 8:
		value = uint64(b[1]) |
			uint64(b[2])<<8 |
			uint64(b[3])<<16 |
			uint64(b[4])<<24 |
			uint64(b[5])<<32 |
			uint64(b[6])<<40 |
			uint64(b[7])<<48 |
			uint64(b[8])<<56
	}

	return
}

// Len returns the length in bytes of the canonical encoding of the value.
func Len(value uint64) int {
	if value < 128 {
		return 1
	}

	return 1 + (bits.Len64(value)+7)>>3
}
