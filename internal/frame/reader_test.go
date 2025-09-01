package frame_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/yat/yat/internal/frame"
)

func TestReader(t *testing.T) {
	buf := frame.Append(nil, 2, frame.Bytes("hello"))
	fr := frame.NewReader(bytes.NewReader(buf))

	hdr, err := fr.Next()
	if err != nil {
		t.Fatal(err)
	}

	if got, want := hdr.Type, frame.Type(2); got != want {
		t.Errorf("type %v != %v", got, want)
	}

	if got, want := hdr.Len, uint32(13); got != want {
		t.Errorf("len %v != %v", got, want)
	}

	body, err := io.ReadAll(fr)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := string(body), "hello"; got != want {
		t.Errorf("body %q != %q", got, want)
	}
}
