package yat

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func Test_frameHdr(t *testing.T) {
	const (
		typ = byte(0x7f)
		len = 0x00a1b2
	)

	h := frameHdr(uint32(typ)<<24 | len)

	if got := h.Len(); got != len {
		t.Fatalf("Len: %d != %d", got, len)
	}

	if got := h.BodyLen(); got != len-4 {
		t.Fatalf("BodyLen: %d != %d", got, len-4)
	}

	if got := h.Type(); got != typ {
		t.Fatalf("Type: %d != %d", got, typ)
	}
}

func Test_readFrameHdr(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		// len=u24le (0x001234), type=5
		src := []byte{0x34, 0x12, 0x00, 0x05}

		h, err := readFrameHdr(bytes.NewReader(src))
		if err != nil {
			t.Fatal(err)
		}

		if got := h.Len(); got != 0x001234 {
			t.Fatalf("Len: %d != %d", got, 0x001234)
		}

		if got := h.Type(); got != 5 {
			t.Fatalf("Type: %d != %d", got, 5)
		}
	})

	t.Run("short", func(t *testing.T) {
		_, err := readFrameHdr(bytes.NewReader([]byte{1, 2, 3}))
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("error: %v", err)
		}
	})
}
