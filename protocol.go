package yat

import (
	"encoding/binary"
	"errors"
	"io"
	"net/http"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
)

func init() {
	uuid.EnableRandPool()
}

// grpcFrmHdr is the first 5 bytes of a gRPC stream frame.
type grpcFrmHdr [grpcFrmHdrLen]byte

// grpcFrmHdrLen is the length in bytes of a gRPC stream frame header.
const grpcFrmHdrLen = 5

const (
	ackField    = 1
	pathField   = 2
	inboxField  = 3
	dataField   = 4
	uuidField   = 5
	limitField  = 6
	statusField = 7
	// handlerField = 8
)

// uuidFieldLen is the length in bytes of a server-appended uuid field.
const uuidFieldLen = 18

// postboxFieldLen is maximum length in bytes of a server-appended
// path field containing a router postbox.
const postboxFieldLen = 69

// maxPubMsgLen is the maximum body length in bytes of a pub stream frame.
// It's a little less than 4M to match the common gRPC size limit,
// and to leave space for a server-appended uuid field.
const maxPubMsgLen = (4 << 20) - uuidFieldLen - postboxFieldLen

// maxSubBufLen is the maximum length in bytes of a subscription's send buffer.
// When a sub's send buffer is full, new deliveries are dropped.
const maxSubBufLen = maxPubMsgLen + (maxPubMsgLen / 2)

var (
	errEmptyPath = errors.New("empty path")
	errLongData  = errors.New("long data")
	errNilFunc   = errors.New("nil func")
	errPostbox   = errors.New("invalid postbox")
	errWildInbox = errors.New("wild inbox path")
	errWildPath  = errors.New("wild path")
	errNegLimit  = errors.New("negative limit")
)

var (
	httpErrPerms = httpError{http.StatusForbidden, "permission denied"}
)

var (
	// rpcErrLongData  = status.Error(codes.InvalidArgument, errLongData.Error())
	rpcErrNegLimit  = status.Error(codes.InvalidArgument, errNegLimit.Error())
	rpcErrNoHandler = status.Error(codes.Unavailable, "no handler for post")
	rpcErrPerms     = status.Error(codes.PermissionDenied, "permission denied")
	rpcErrPostbox   = status.Error(codes.InvalidArgument, errPostbox.Error())
	rpcErrWildInbox = status.Error(codes.InvalidArgument, errWildInbox.Error())
	rpcErrWildPath  = status.Error(codes.InvalidArgument, errWildPath.Error())
)

func (h grpcFrmHdr) IsCompressed() bool {
	return h[0] != 0
}

func (h grpcFrmHdr) BodyLen() int {
	return int(binary.BigEndian.Uint32(h[1:]))
}

func appendGRPCFrm(b []byte, f func(b []byte) []byte) []byte {
	i := len(b)
	b = f(append(b, 0, 0, 0, 0, 0))
	binary.BigEndian.PutUint32(b[i+1:], uint32(len(b)-i-grpcFrmHdrLen))
	return b
}

func readGRPCFrmHdr(r io.Reader) (hdr grpcFrmHdr, err error) {
	_, err = io.ReadFull(r, hdr[:])
	if err != nil {
		return
	}

	if hdr.IsCompressed() {
		return hdr, errors.New("compressed frame")
	}

	if hdr.BodyLen() > maxPubMsgLen {
		return hdr, errors.New("long frame")
	}

	return
}

func parseMsgPath(raw []byte) (Path, error) {
	path, err := ParsePath(raw)
	if err != nil {
		return Path{}, invalid(err)
	}

	if path.IsWild() {
		return path, rpcErrWildPath
	}

	return path, nil
}

// parseMsgInboxFromClient is called by the server to parse an optional message inbox.
// If the raw path is empty, the zero path is returned.
func parseMsgInboxFromClient(raw []byte) (Path, error) {
	if len(raw) == 0 {
		return Path{}, nil
	}

	inbox, err := ParsePath(raw)
	if err != nil {
		return Path{}, invalid(err)
	}

	if inbox.IsWild() {
		return inbox, rpcErrWildInbox
	}

	if inbox.IsPostbox() {
		return inbox, rpcErrPostbox
	}

	return inbox, nil
}

// parseMsgInboxFromServer is called by the client to parse an optional message inbox.
// Unline parseMsgInboxFromClient, postboxes are allowed.
// If the raw path is empty, the zero path is returned.
func parseMsgInboxFromServer(raw []byte) (Path, error) {
	if len(raw) == 0 {
		return Path{}, nil
	}

	inbox, err := ParsePath(raw)
	if err != nil {
		return Path{}, err
	}

	if inbox.IsWild() {
		return inbox, rpcErrWildInbox
	}

	return inbox, nil
}

// parseSelPath parses a path like parseMsgPath,
// but the returned path may be wild.
func parseSelPath(raw []byte) (Path, error) {
	path, err := ParsePath(raw)
	if err != nil {
		return Path{}, invalid(err)
	}

	if path.IsPostbox() {
		return Path{}, rpcErrPostbox
	}

	return path, nil
}

func parseLimit(v int64) (int, error) {
	if v < 0 {
		return 0, rpcErrNegLimit
	}
	return int(v), nil
}

func readMsgPubFrm(r io.Reader) (hdr grpcFrmHdr, frm []byte, err error) {
	hdr, err = readGRPCFrmHdr(r)
	if err != nil {
		return
	}

	flen := grpcFrmHdrLen + hdr.BodyLen()

	// extra cap for possible server-appended fields
	fcap := flen + uuidFieldLen + postboxFieldLen

	// round to the nearest page
	fcap = (fcap + 4095) &^ 4095
	frm = make([]byte, flen, fcap)

	// reconstruct
	copy(frm, hdr[:])
	body := frm[grpcFrmHdrLen:]
	_, err = io.ReadFull(r, body)

	// short body
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}

	return
}

// parseMsgPubFrm parses a gRPC stream frame containing a PubRequest or MpubRequest.
// It cleans and updates the frame in place, removing fields other than
// path (2), inbox (3), and data (4).
//
// The returned clean frame and fields alias the original frame.
func parseMsgPubFrm(frm []byte) (clean []byte, fields msgPubFields, err error) {
	req := frm[grpcFrmHdrLen:]
	res := req[:0]
	in, out := 0, 0

	for in < len(req) {
		fnum, ftyp, nt := protowire.ConsumeTag(req[in:])
		if err = protowire.ParseError(nt); err != nil {
			return
		}

		switch fnum {
		case ackField:
			if ftyp != protowire.VarintType {
				err = errors.New("not a varint")
				return
			}

			var nv int
			fields.Ack, nv = protowire.ConsumeVarint(req[in+nt:])
			if err = protowire.ParseError(nv); err != nil {
				return
			}

			in += nt + nv

		case pathField, inboxField, dataField:
			if ftyp != protowire.BytesType {
				err = errors.New("not bytes")
				return
			}

			v, nv := protowire.ConsumeBytes(req[in+nt:])
			if err = protowire.ParseError(nv); err != nil {
				return
			}

			var dst *[]byte
			switch fnum {
			case pathField:
				dst = &fields.Path

			case inboxField:
				dst = &fields.Inbox

			case dataField:
				dst = &fields.Data
			}

			n := nt + nv
			if *dst != nil {
				in += n
				continue
			}

			if out != in {
				copy(req[out:], req[in:in+n])
			}

			start := out + n - len(v)
			*dst = req[start : out+n : out+n]
			out += n
			in += n
			res = req[:out]

		default:
			nv := protowire.ConsumeFieldValue(fnum, ftyp, req[in+nt:])
			if err = protowire.ParseError(nv); err != nil {
				return
			}

			in += nt + nv
		}
	}

	binary.BigEndian.PutUint32(frm[1:grpcFrmHdrLen], uint32(len(res)))
	clean = frm[:grpcFrmHdrLen+len(res)]
	return
}

type msgPubFields struct {
	Ack   uint64 // only appears in mpub frames
	Path  []byte
	Inbox []byte
	Data  []byte
}

func (f msgPubFields) Parse() (valid Msg, err error) {
	valid.Path, err = parseMsgPath(f.Path)
	if err != nil {
		return
	}

	valid.Inbox, err = parseMsgInboxFromClient(f.Inbox)
	if err != nil {
		return
	}

	valid.Data = f.Data
	if len(valid.Data) > MaxDataLen {
		err = invalid(errLongData)
		return
	}

	return
}

// parseMsgPubFrm parses a gRPC stream frame containing a PubRequest or MpubRequest.
// It cleans and updates the frame in place, removing fields other than
// path (2), inbox (3), and data (4).
//
// The returned clean frame and fields alias the original frame.
func parseMsgPostFrm(frm []byte) (clean []byte, fields msgPostFields, err error) {
	req := frm[grpcFrmHdrLen:]
	res := req[:0]
	in, out := 0, 0

	for in < len(req) {
		fnum, ftyp, nt := protowire.ConsumeTag(req[in:])
		if err = protowire.ParseError(nt); err != nil {
			return
		}

		switch fnum {
		case limitField:
			if ftyp != protowire.VarintType {
				err = errors.New("not a varint")
				return
			}

			lim, nv := protowire.ConsumeVarint(req[in+nt:])
			if err = protowire.ParseError(nv); err != nil {
				return
			}

			fields.Limit = int64(lim)
			in += nt + nv

		case pathField, dataField:
			if ftyp != protowire.BytesType {
				err = errors.New("not bytes")
				return
			}

			v, nv := protowire.ConsumeBytes(req[in+nt:])
			if err = protowire.ParseError(nv); err != nil {
				return
			}

			var dst *[]byte
			switch fnum {
			case pathField:
				dst = &fields.Path

			case dataField:
				dst = &fields.Data
			}

			n := nt + nv
			if *dst != nil {
				in += n
				continue
			}

			if out != in {
				copy(req[out:], req[in:in+n])
			}

			start := out + n - len(v)
			*dst = req[start : out+n : out+n]
			out += n
			in += n
			res = req[:out]

		default:
			nv := protowire.ConsumeFieldValue(fnum, ftyp, req[in+nt:])
			if err = protowire.ParseError(nv); err != nil {
				return
			}

			in += nt + nv
		}
	}

	binary.BigEndian.PutUint32(frm[1:grpcFrmHdrLen], uint32(len(res)))
	clean = frm[:grpcFrmHdrLen+len(res)]
	return
}

type msgPostFields struct {
	Limit int64
	Path  []byte
	Data  []byte
}

func (f msgPostFields) Parse() (path Path, data []byte, err error) {
	path, err = parseMsgPath(f.Path)
	if err != nil {
		return
	}

	if path.IsPostbox() {
		err = rpcErrPostbox
		return
	}

	if len(f.Data) > MaxDataLen {
		err = invalid(errLongData)
		return
	}

	data = f.Data
	return
}

type httpError struct {
	Status  int
	Message string
}

func (e httpError) Error() string {
	return e.Message
}

func invalid(err error) error {
	return status.Error(codes.InvalidArgument, err.Error())
}

// validateOutboundMsg validates a message passed to Publish or Send.
func validateOutboundMsg(m Msg) error {
	if m.Path.IsZero() {
		return errEmptyPath
	}

	if m.Path.IsWild() {
		return errWildPath
	}

	if m.Inbox.IsWild() {
		return errWildInbox
	}

	if m.Inbox.IsPostbox() {
		return errPostbox
	}

	if len(m.Data) > MaxDataLen {
		return errLongData
	}

	return nil
}

// validateOutboundSel validates a selector passed to Subscribe.
func validateOutboundSel(s Sel) error {
	if s.Path.IsZero() {
		return errEmptyPath
	}

	if s.Path.IsPostbox() {
		return errPostbox
	}

	if s.Limit < 0 {
		return errNegLimit
	}

	return nil
}

// validateOutboundReq validates a selector passed to Post.
func validateOutboundReq(r Req) error {
	if r.Path.IsZero() {
		return errEmptyPath
	}

	if r.Path.IsWild() {
		return errWildPath
	}

	if r.Path.IsPostbox() {
		return errPostbox
	}

	if len(r.Data) > MaxDataLen {
		return errLongData
	}

	if r.Limit < 0 {
		return errNegLimit
	}

	return nil
}

// validateEOF returns an error if r is not at EOF.
func validateEOF(r io.Reader) error {
	n, err := r.Read(make([]byte, 1))
	if err != nil && err != io.EOF {
		return err
	}

	if n > 0 {
		return errors.New("trailing bytes")
	}

	return nil
}
