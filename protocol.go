package yat

import (
	"errors"
	"io"
	"slices"
	"unsafe"

	"google.golang.org/protobuf/encoding/protowire"
)

const (
	MinFrameLen = frameHdrLen
	MaxFrameLen = 1<<24 - 1
)

// type frameHdr struct {
// 	Len  uint24
// 	Type byte
// }

type frameHdr uint32

const frameHdrLen = 4

const (
	_              = 0
	jwtFrameType   = 1
	pubFrameType   = 2
	subFrameType   = 3
	unsubFrameType = 4
	msgFrameType   = 16
)

const (
	numField   = 1
	pathField  = 2
	dataField  = 3
	inboxField = 4
)

var (
	errShortFrame  = errors.New("short frame")
	errLongFrame   = errors.New("long frame")
	errDupJWTFrame = errors.New("duplicate jwt frame")
	errEmptyPath   = errors.New("empty path")
	errSelPath     = errors.New("selector path changed")
	errWildPath    = errors.New("wildcard path")
	errWildInbox   = errors.New("wildcard inbox")
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

// appendFrameBytes appends a frame header and static body to buf and returns the extended slice.
func appendFrameBytes(buf []byte, typ byte, body []byte) []byte {
	return appendFrame(buf, typ, func(b []byte) []byte {
		return append(b, body...)
	})
}

// parseMsg parses a proto into a message.
// It returns the parsed num field, parsed message, and its raw backing proto.
// The returned message is valid.
//
// The given body is compacted, retaining only fields 2 (path), 3 (data), and 4 (inbox).
// If field 1 (num) is encountered, its value is returned.
// The returned message and its raw backing slice alias the body.
//
// This function does not allocate.
func parseMsg(body []byte) (num uint64, msg Msg, raw []byte, err error) {
	out := 0
	raw = body[:0]

	for in := 0; in < len(body); {
		fn, typ, nt := protowire.ConsumeTag(body[in:])
		if nt < 0 {
			err = protowire.ParseError(nt)
			return
		}

		if fn == numField {
			if typ != protowire.VarintType {
				err = errors.New("invalid field type")
				return
			}

			v, nv := protowire.ConsumeVarint(body[in+nt:])
			if nv < 0 {
				err = protowire.ParseError(nv)
				return
			}
			num = v

			in += nt + nv
			continue
		}

		if fn != pathField && fn != dataField && fn != inboxField {
			nval := protowire.ConsumeFieldValue(fn, typ, body[in+nt:])
			if nval < 0 {
				err = protowire.ParseError(nval)
				return
			}

			in += nt + nval
			continue
		}

		if typ != protowire.BytesType {
			err = errors.New("invalid field type")
			return
		}

		_, nv := protowire.ConsumeBytes(body[in+nt:])
		if nv < 0 {
			err = protowire.ParseError(nv)
			return
		}

		n := nt + nv
		if out != in {
			copy(body[out:], body[in:in+n])
		}

		out += n
		in += n
		raw = body[:out]
	}

	for clean := raw; len(clean) > 0; {
		fn, _, nt := protowire.ConsumeTag(clean)
		v, nv := protowire.ConsumeBytes(clean[nt:])
		clean = clean[nt+nv:]

		switch fn {
		case pathField:
			var wild bool
			msg.Path, wild, err = ParsePath(v)
			if err != nil {
				return
			}

			if wild {
				err = errWildPath
				return
			}

		case dataField:
			msg.Data = v

		case inboxField:
			var wild bool
			msg.Inbox, wild, err = ParsePath(v)
			if err != nil {
				return
			}

			if wild {
				err = errWildInbox
				return
			}
		}
	}

	if msg.Path.IsZero() {
		err = errEmptyPath
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

// msgFieldsLen returns the length of the proto-encoded version of the message.
func msgFieldsLen(m Msg) int {
	n := protowire.SizeTag(pathField) +
		protowire.SizeBytes(len(m.Path.p))

	if len(m.Data) > 0 {
		n += protowire.SizeTag(dataField) +
			protowire.SizeBytes(len(m.Data))
	}

	if !m.Inbox.IsZero() {
		n += protowire.SizeTag(inboxField) +
			protowire.SizeBytes(len(m.Inbox.p))
	}

	return n
}

// isWild returns true if the path contains a * or ** wildcard.
func isWild(p Path) bool {
	return slices.Contains(p.p, '*')
}
