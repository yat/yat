// Package frame provides a simple framing protocol for byte streams.
//
// A frame starts with an 8 byte [Header].
// The header is a u32le frame length (including the header) followed by
// a u16le frame type. The final 2 header bytes are reserved.
//
// The header is followed by (frame length - 8) bytes of frame body.
package frame

import (
	"encoding/binary"
)

// Header is the first 8 bytes of a frame.
// It has the same representation in memory and on the wire.
type Header struct {
	Len  uint32  // frame length in bytes including the header
	Type Type    // describes the frame body
	_    [2]byte // reserved for future flags
}

type Type uint16

// NoType is the zero frame type.
const NoType = 0

const headerLen = 8

var ByteOrder = binary.LittleEndian

// BodyAppender is the interface called by Append to append a frame's body to a buffer.
type BodyAppender interface {
	AppendBody([]byte) []byte
}

// Append appends a frame with the given type and body to b and returns the extended buffer.
// If body is nil, the appended frame will be empty.
func Append(b []byte, typ Type, body BodyAppender) []byte {
	i := len(b)
	b = AppendHeader(b, typ, 0)

	if body == nil {
		return b
	}

	b = body.AppendBody(b)

	// update the frame len
	ByteOrder.PutUint32(b[i:], uint32(len(b)-i))

	return b
}

func AppendHeader(b []byte, typ Type, bodyLen int) []byte {
	b = ByteOrder.AppendUint32(b, uint32(headerLen+bodyLen))
	b = ByteOrder.AppendUint16(b, uint16(typ))
	b = append(b, 0, 0) // reserved
	return b
}

// BodyLen returns the length of the frame body in bytes.
func (h Header) BodyLen() int {
	return int(h.Len - headerLen)
}

type Bytes []byte

func (bb Bytes) AppendBody(b []byte) []byte {
	return append(b, bb...)
}
