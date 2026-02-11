package yat

import (
	"io"
	"unsafe"
)

const (
	MinFrameLen = 4
	MaxFrameLen = 1<<24 - 1
)

type frameHdr uint32

// type frameHdr struct {
// 	Len  uint24
// 	Type byte
// }

const (
	_              = 0
	pubFrameType   = 1
	subFrameType   = 2
	unsubFrameType = 3
	msgFrameType   = 4
)

func (h frameHdr) Len() int {
	return int(h & 0x00ffffff)
}

func (h frameHdr) BodyLen() int {
	return h.Len() - int(unsafe.Sizeof(h))
}

func (h frameHdr) Type() byte {
	return byte(h >> 24)
}

func readFrameHdr(r io.Reader) (hdr frameHdr, err error) {
	_, err = io.ReadFull(r, (*(*[4]byte)(unsafe.Pointer(&hdr)))[:])
	return
}
