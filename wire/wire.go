// Package wire implements the binary protocol used by Yat clients and servers.
// The protocol is designed to minimize codec branches rather than bytes on the wire.
// To run the protocol, peers read and write frames over a reliable full-duplex connection.
// The peer who initates the connection is the client and the peer who accepts it is the server.
//
// # Encoding
//
// A frame is an 8 byte header followed by an optional body.
// The frame header is a u32le frame len followed by a u32le frame type.
// The frame len includes the header, so it is always >= 8.
package wire

import (
	"encoding/binary"
	"errors"
	"io"
	"unsafe"
)

type FrameHdr struct {
	Len  uint32
	Type uint32
}

type PingFrameBody struct {
	ID uint32
	_  [4]byte
}

type PubFrameBody struct {
	Msg
}

type ReqFrameBody struct {
	ID   uint32
	Data []byte
	Path []byte
}

type SubFrameBody struct {
	ID    uint32
	Limit uint32
	Path  []byte
	Group []byte
}

type UnsubFrameBody struct {
	ID uint32
	_  [4]byte
}

type PongFrameBody struct {
	ID uint32
	_  [4]byte
}

type PkgFrameBody struct {
	ID    uint32
	Errno uint32
	Msg   Msg
}

type Msg struct {
	Data  []byte
	Path  []byte
	Reply []byte
}

const (
	FAUTH  = 1
	FPING  = 2
	FPUB   = 3
	FREQ   = 4
	FSUB   = 5
	FUNSUB = 6
	FPONG  = 65
	FPKG   = 66
)

type reqFrameHdr struct {
	ID      uint32
	_       [4]byte
	DataLen uint32
	PathLen uint16

	// This padding allows the last 8 bytes of this header
	// to serve as a msgHdr. When a req frame is received,
	// the server appends a generated reply path and updates
	// these 2 bytes in place to create a message buffer.
	_ [2]byte
}

type subFrameHdr struct {
	ID       uint32
	Limit    uint32
	_        [4]byte
	PathLen  uint16
	GroupLen uint16
}

type pkgFrameHdr struct {
	ID    uint32
	Errno uint32
	Msg   msgHdr
}

type msgHdr struct {
	DataLen  uint32
	PathLen  uint16
	ReplyLen uint16
}

const (
	frameHdrLen    = int(unsafe.Sizeof(FrameHdr{}))
	reqFrameHdrLen = int(unsafe.Sizeof(reqFrameHdr{}))
	subFrameHdrLen = int(unsafe.Sizeof(subFrameHdr{}))
	pkgFrameHdrLen = int(unsafe.Sizeof(pkgFrameHdr{}))
	msgHdrLen      = int(unsafe.Sizeof(msgHdr{}))
)

var (
	errShortFrame  = errors.New("short frame")
	errShortBuffer = errors.New("short buffer")
)

var bo = binary.LittleEndian

func AppendFrame(b []byte, typ uint32, f func([]byte) []byte) []byte {
	i := len(b)

	// hdr
	b = bo.AppendUint32(b, uint32(frameHdrLen))
	b = bo.AppendUint32(b, typ)

	// body
	b = f(b)

	// update hdr
	bo.PutUint32(b[i:], uint32(len(b)-i))

	return b
}

func ReadFrameHdr(r io.Reader, h *FrameHdr) error {
	b := unsafe.Slice((*byte)(unsafe.Pointer(h)), frameHdrLen)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}

	if h.Len < uint32(frameHdrLen) {
		return errShortFrame
	}

	return nil
}

func (fh FrameHdr) Encode(b []byte) []byte {
	return unsafeEncode(b, fh)
}

// BodyLen return the length of the frame body following the header.
func (fh FrameHdr) BodyLen() int {
	return int(fh.Len) - frameHdrLen
}

func (fb PingFrameBody) Encode(b []byte) []byte {
	return unsafeEncode(b, fb)
}

func (fb *PingFrameBody) Decode(b []byte) (n int, err error) {
	return unsafeDecode(fb, b)
}

func (fb ReqFrameBody) Encode(b []byte) []byte {
	b = unsafeEncode(b, reqFrameHdr{
		ID:      fb.ID,
		DataLen: uint32(len(fb.Data)),
		PathLen: uint16(len(fb.Path)),
	})

	b = append(b, fb.Data...)
	b = append(b, fb.Path...)

	return b
}

func (fb *ReqFrameBody) Decode(b []byte) (n int, err error) {
	var h reqFrameHdr
	n, err = unsafeDecode(&h, b)
	if err != nil {
		return
	}

	if len(b) < h.EncodedLen() {
		return n, errShortBuffer
	}

	*fb = ReqFrameBody{
		ID: h.ID,
	}

	n = h.EncodedLen()
	fields := b[reqFrameHdrLen:n]

	poff := int(h.DataLen)
	fb.Data = fields[:poff]
	fb.Path = fields[poff:]

	return
}

func (h reqFrameHdr) EncodedLen() int {
	return reqFrameHdrLen + int(h.DataLen) + int(h.PathLen)
}

func (fb SubFrameBody) Encode(b []byte) []byte {
	return append(append(unsafeEncode(b, subFrameHdr{
		ID:       fb.ID,
		Limit:    fb.Limit,
		PathLen:  uint16(len(fb.Path)),
		GroupLen: uint16(len(fb.Group)),
	}), fb.Path...), fb.Group...)
}

func (fb *SubFrameBody) Decode(b []byte) (n int, err error) {
	var h subFrameHdr
	n, err = unsafeDecode(&h, b)
	if err != nil {
		return
	}

	if len(b) < h.EncodedLen() {
		return n, errShortBuffer
	}

	n = h.EncodedLen()
	fields := b[subFrameHdrLen:n]
	plen := int(h.PathLen)

	*fb = SubFrameBody{
		ID:    h.ID,
		Limit: h.Limit,
		Path:  fields[:plen],
		Group: fields[plen:],
	}

	return
}

func (h subFrameHdr) EncodedLen() int {
	return subFrameHdrLen + int(h.PathLen) + int(h.GroupLen)
}

func (fb UnsubFrameBody) Encode(b []byte) []byte {
	return unsafeEncode(b, fb)
}

func (fb *UnsubFrameBody) Decode(b []byte) (n int, err error) {
	return unsafeDecode(fb, b)
}

func (fb PongFrameBody) Encode(b []byte) []byte {
	return unsafeEncode(b, fb)
}

func (fb *PongFrameBody) Decode(b []byte) (n int, err error) {
	return unsafeDecode(fb, b)
}

func (fb PkgFrameBody) Encode(b []byte) []byte {
	return fb.Msg.appendFields(unsafeEncode(b, pkgFrameHdr{
		ID:    fb.ID,
		Errno: fb.Errno,
		Msg:   fb.Msg.hdr(),
	}))
}

func (fb *PkgFrameBody) Decode(b []byte) (n int, err error) {
	var h pkgFrameHdr
	n, err = unsafeDecode(&h, b)
	if err != nil {
		return
	}

	if len(b) < h.EncodedLen() {
		return n, errShortBuffer
	}

	*fb = PkgFrameBody{
		ID:    h.ID,
		Errno: h.Errno,
	}

	n = h.EncodedLen()
	fields := b[pkgFrameHdrLen:n]
	fb.Msg.decodeFields(h.Msg, fields)

	return
}

func (h pkgFrameHdr) EncodedLen() int {
	return int(unsafe.Offsetof(h.Msg)) + h.Msg.EncodedLen()
}

func (m Msg) Encode(b []byte) []byte {
	return m.appendFields(unsafeEncode(b, m.hdr()))
}

func (m *Msg) Decode(b []byte) (n int, err error) {
	var h msgHdr
	n, err = unsafeDecode(&h, b)
	if err != nil {
		return
	}

	if len(b) < h.EncodedLen() {
		return n, errShortBuffer
	}

	n = h.EncodedLen()
	fb := b[msgHdrLen:n]
	m.decodeFields(h, fb)

	return
}

func (m Msg) appendFields(b []byte) []byte {
	b = append(b, m.Data...)
	b = append(b, m.Path...)
	b = append(b, m.Reply...)
	return b
}

func (m *Msg) decodeFields(h msgHdr, fields []byte) {
	poff := int(h.DataLen)
	roff := poff + int(h.PathLen)

	*m = Msg{
		Data:  fields[:poff],
		Path:  fields[poff:roff],
		Reply: fields[roff:],
	}
}

func (m Msg) hdr() msgHdr {
	return msgHdr{
		DataLen:  uint32(len(m.Data)),
		PathLen:  uint16(len(m.Path)),
		ReplyLen: uint16(len(m.Reply)),
	}
}

func (h msgHdr) EncodedLen() int {
	return msgHdrLen + int(h.DataLen) + int(h.PathLen) + int(h.ReplyLen)
}

func unsafeEncode[T any](b []byte, v T) []byte {
	return append(b, unsafe.Slice((*byte)(unsafe.Pointer(&v)), unsafe.Sizeof(v))...)
}

func unsafeDecode[T any](v *T, b []byte) (n int, err error) {
	sz := int(unsafe.Sizeof(*v))
	if len(b) < sz {
		return 0, errShortBuffer
	}

	vb := unsafe.Slice((*byte)(unsafe.Pointer(v)), sz)
	return copy(vb, b), nil
}
