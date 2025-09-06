// Package uid generates random identifiers with the same bit pattern as UUIDv4.
package uid

import (
	"crypto/rand"
	"encoding/base32"
)

// ID is a random identifier.
// Create one by calling [New].
type ID [16]byte

// New returns a random identifier.
func New() (id ID) {
	rand.Read(id[:])
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	return
}

var b32 = base32.NewEncoding("0123456789abcdefghijklmnopqrstuv").WithPadding(base32.NoPadding)

// String returns the ID formatted as an unpadded base32 string
// using the alphabet "0123456789abcdefghijklmnopqrstuv".
func (id ID) String() string {
	return b32.EncodeToString(id[:])
}
