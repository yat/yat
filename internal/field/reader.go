package field

import (
	"errors"
	"io"

	"github.com/yat/yat/internal/nv"
)

// Reader reads fields from an encoded field set.
type Reader struct {
	b []byte
	e error
}

var ErrShort = errors.New("short field")
var ErrOverflow = errors.New("value overflows 64 bits")

func NewReader(b []byte) *Reader {
	r := &Reader{}
	r.Reset(b)
	return r
}

func (r *Reader) ReadTag() (tag Tag, err error) {
	if r.e != nil {
		err = r.e
		return
	}

	if len(r.b) == 0 {
		err = io.EOF
		r.e = err
		return
	}

	tag = Tag(r.b[0])
	r.b = r.b[1:]
	return
}

func (r *Reader) ReadNum() (value uint64, err error) {
	if r.e != nil {
		err = r.e
		return
	}

	value, n := nv.Parse(r.b)

	switch {
	case n == 0:
		err = ErrShort
		r.e = err
		return

	case n < 0:
		err = ErrOverflow
		r.e = err
		return
	}

	r.b = r.b[n:]
	return
}

func (r *Reader) ReadRun() (run []byte, err error) {
	if r.e != nil {
		err = r.e
		return
	}

	rlen, err := r.ReadNum()
	if err != nil {
		return
	}

	if uint64(len(r.b)) < rlen {
		err = ErrShort
		r.e = err
		return
	}

	run = r.b[:rlen]
	r.b = r.b[rlen:]
	return
}

func (r *Reader) Discard(t Tag) error {
	if r.e != nil {
		return r.e
	}

	count := 1
	if t.Card() != One {
		v, err := r.ReadNum()
		if err != nil {
			return err
		}

		count = int(v)
	}

	for range count {
		// num value or run len
		val, err := r.ReadNum()
		if err != nil {
			return err
		}

		// if run, discard data
		if t.Type() == Run {
			if uint64(len(r.b)) < val {
				r.e = ErrShort
				return ErrShort
			}
			r.b = r.b[val:]
		}
	}

	return nil
}

// Reset resets r to read from b.
func (r *Reader) Reset(b []byte) {
	*r = Reader{b: b}
}
