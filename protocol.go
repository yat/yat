package yat

import (
	"errors"
	"io"
	"slices"
	"unsafe"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"yat.io/yat/wire"
)

// type frameHdr struct {
// 	Len  uint24
// 	Type byte
// }

// frameHdr holds the first 4 bytes of a wire frame.
// b0-b2 are the u24le frame length including the header.
// b3 is the frame type.
type frameHdr uint32

// sharedFields captures all the fields parsed by [parseFields].
type sharedFields struct {
	Num uint64
	Msg
}

const (
	frameHdrLen      = 4
	minFrameLen      = frameHdrLen
	maxMsgDataLen    = 8 << 20
	maxClientDataLen = 32 << 20
	maxSvrConnBufLen = 32 << 20
)

const (
	_              = 0
	_              = 1
	pubFrameType   = 2
	subFrameType   = 4
	unsubFrameType = 5
	msgFrameType   = 16
)

const (
	numField   = 1
	pathField  = 2
	dataField  = 3
	inboxField = 4
)

var (
	errShortFrame = errors.New("short frame")
	errBufferFull = errors.New("buffer full")
	errEmptyPath  = errors.New("empty path")
	errWildPath   = errors.New("wildcard path")
	errWildInbox  = errors.New("wildcard inbox")
	errLongData   = errors.New("long data")
	errLongGroup  = errors.New("long group")
	errLimitRange = errors.New("limit out of range")
	errDupSub     = errors.New("duplicate subscription number")
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

func appendSubFrame(buf []byte, num uint64, sel Sel) []byte {
	sf := &wire.SubFrame{
		Num:  num,
		Path: sel.Path.p,
	}

	if !sel.Group.IsZero() {
		sf.Group = []byte(sel.Group.String())
	}

	if limit := max(0, min(sel.Limit, MaxLimit)); limit > 0 {
		sf.Limit = int64(limit)
	}

	return appendFrame(buf, subFrameType, func(b []byte) []byte {
		b, _ = proto.MarshalOptions{}.MarshalAppend(b, sf)
		return b
	})
}

// appendFrame appends a frame header and body to buf and returns the extended slice.
// The body comes from calling f, which must append to its argument and return the extended slice.
func appendFrame(buf []byte, typ byte, f func([]byte) []byte) []byte {
	off := len(buf)
	buf = append(buf, 0, 0, 0, typ)
	buf = f(buf)

	n := len(buf) - off
	buf[off+0] = byte(n)
	buf[off+1] = byte(n >> 8)
	buf[off+2] = byte(n >> 16)

	return buf
}

// parseFields parses a raw proto and extracts shared fields:
// num (1; varint), path (2; bytes), data (3; bytes), inbox (4; bytes), and status (5; varint).
// It also destructively cleans the raw proto, preserving only fields 2, 3, and 4.
// The returned fields.Msg and msg bytes alias the raw proto.
func parseFields(raw []byte) (fields sharedFields, msg []byte, err error) {
	in, out := 0, 0
	msg = raw[:0]

	// clean the proto
	for in < len(raw) {
		fnum, ftyp, nt := protowire.ConsumeTag(raw[in:])
		if err = protowire.ParseError(nt); err != nil {
			return
		}

		switch fnum {
		case numField:
			if ftyp != protowire.VarintType {
				err = errors.New("not a varint")
				return
			}

			num, nv := protowire.ConsumeVarint(raw[in+nt:])
			if err = protowire.ParseError(nv); err != nil {
				return
			}

			fields.Num = num
			in += nt + nv

		case pathField, dataField, inboxField:
			if ftyp != protowire.BytesType {
				err = errors.New("not bytes")
				return
			}

			_, nv := protowire.ConsumeBytes(raw[in+nt:])
			if err = protowire.ParseError(nv); err != nil {
				return
			}

			n := nt + nv
			if out != in {
				copy(raw[out:], raw[in:in+n])
			}

			out += n
			in += n
			msg = raw[:out]

		default:
			nv := protowire.ConsumeFieldValue(fnum, ftyp, raw[in+nt:])
			if err = protowire.ParseError(nv); err != nil {
				return
			}

			in += nt + nv
		}
	}

	// parse the msg fields
	for clean := msg; len(clean) > 0; {
		fn, typ, nt := protowire.ConsumeTag(clean)
		if err = protowire.ParseError(nt); err != nil {
			return
		}
		if typ != protowire.BytesType {
			err = errors.New("not bytes")
			return
		}

		v, nv := protowire.ConsumeBytes(clean[nt:])
		if err = protowire.ParseError(nv); err != nil {
			return
		}
		clean = clean[nt+nv:]

		switch fn {
		case pathField:
			fields.Path, _, err = ParsePath(v)
			if err != nil {
				return
			}

		case dataField:
			fields.Data = v

		case inboxField:
			fields.Inbox, _, err = ParsePath(v)
			if err != nil {
				return
			}
		}
	}

	return
}

func appendMsgFields(b []byte, m Msg) []byte {
	b = protowire.AppendTag(b, pathField, protowire.BytesType)
	b = protowire.AppendBytes(b, m.Path.p)

	if len(m.Data) > 0 {
		b = protowire.AppendTag(b, dataField, protowire.BytesType)
		b = protowire.AppendBytes(b, m.Data)
	}

	if !m.Inbox.IsZero() {
		b = protowire.AppendTag(b, inboxField, protowire.BytesType)
		b = protowire.AppendBytes(b, m.Inbox.p)
	}

	return b
}

// aliasMsgFields returns a Msg with fields backed by the raw proto.
// The encoded message must already be valid.
func aliasMsgFields(raw []byte) (msg Msg) {
	for len(raw) > 0 {
		num, _, nt := protowire.ConsumeTag(raw)
		v, nv := protowire.ConsumeBytes(raw[nt:])
		raw = raw[nt+nv:]

		switch num {
		case pathField:
			msg.Path.p = v

		case dataField:
			msg.Data = v

		case inboxField:
			msg.Inbox.p = v
		}
	}

	return
}

// isWild returns true if the path contains a * or ** wildcard.
func isWild(p Path) bool {
	return slices.Contains(p.p, '*')
}

// validatePubFrame validates PubFrame fields.
func validatePubFrame(fields sharedFields) error {
	return validateMsg(fields.Msg)
}

func validateMsg(m Msg) error {
	if m.Path.IsZero() {
		return errEmptyPath
	}

	if isWild(m.Path) {
		return errWildPath
	}

	if isWild(m.Inbox) {
		return errWildInbox
	}

	if len(m.Data) > maxMsgDataLen {
		return errLongData
	}

	return nil
}

func validateSel(s Sel) error {
	if s.Path.IsZero() {
		return errEmptyPath
	}

	if s.Limit < 0 || s.Limit > MaxLimit {
		return errLimitRange
	}

	return nil
}
