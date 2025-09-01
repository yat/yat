package frame

import (
	"io"
	"unsafe"
)

// Reader reads frames from an underlying stream.
// Call Next to advance to the next frame and Read to read its body.
type Reader struct {
	lr io.LimitedReader
	h  Header
}

// NewReader returns a new frame reader wrapping r.
func NewReader(r io.Reader) *Reader {
	var fr Reader
	fr.Reset(r)
	return &fr
}

// Next advances to the next frame in the stream.
// Any remaining data in the current frame is discarded.
// The returned header pointer is valid until Next is called again.
// At the end of the stream, Next returns [io.EOF].
func (r *Reader) Next() (*Header, error) {
	if r.lr.N > 0 {
		if _, err := io.Copy(io.Discard, &r.lr); err != nil {
			return nil, err
		}

		if r.lr.N > 0 {
			return nil, io.ErrUnexpectedEOF
		}
	}

	p := unsafe.Slice((*byte)(unsafe.Pointer(&r.h)), unsafe.Sizeof(r.h))
	if _, err := io.ReadFull(r.lr.R, p); err != nil {
		return nil, err
	}

	r.lr.N = int64(r.h.Len) - int64(unsafe.Sizeof(r.h))
	return &r.h, nil
}

// Read reads from the current frame.
// It returns [io.EOF] when the frame is consumed.
// After EOF, call Next to advance to the next frame.
func (r *Reader) Read(p []byte) (n int, err error) {
	return r.lr.Read(p)
}

func (fr *Reader) Reset(r io.Reader) {
	*fr = Reader{lr: io.LimitedReader{R: r}}
}
