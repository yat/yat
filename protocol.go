package yat

import (
	"errors"
	"io"
	"unsafe"

	"google.golang.org/protobuf/encoding/protowire"
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

const (
	numField   = 1
	pathField  = 2
	dataField  = 3
	inboxField = 4
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

// parseMsg parses a proto into a message.
// It returns the parsed message and its raw backing proto.
// The returned message is valid.
//
// The given body is compacted, retaining fields 2 (path), 3 (data), and 4 (inbox).
// The returned message and its raw backing slice alias the body.
//
// This function does not allocate.
func parseMsg(body []byte) (msg Msg, raw []byte, err error) {
	out := 0
	raw = body[:0]

	for in := 0; in < len(body); {
		num, typ, nt := protowire.ConsumeTag(body[in:])
		if nt < 0 {
			err = protowire.ParseError(nt)
			return
		}

		if num != pathField && num != dataField && num != inboxField {
			nval := protowire.ConsumeFieldValue(num, typ, body[in+nt:])
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
		num, _, nt := protowire.ConsumeTag(clean)
		v, nv := protowire.ConsumeBytes(clean[nt:])
		clean = clean[nt+nv:]

		switch num {
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
