package wire_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/google/go-cmp/cmp"
	"yat.io/yat/wire"
)

func TestFrames(t *testing.T) {
	b := wire.AppendFrame(nil, 1, func(b []byte) []byte {
		return append(b, "hello"...)
	})

	b = wire.AppendFrame(b, 2, func(b []byte) []byte {
		return append(b, "world"...)
	})

	r := bytes.NewReader(b)

	var got wire.FrameHdr
	if err := wire.ReadFrameHdr(r, &got); err != nil {
		t.Fatal(err)
	}

	want := wire.FrameHdr{
		Len:  uint32(8 + len("hello")),
		Type: 1,
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatal(diff)
	}

	body := make([]byte, got.BodyLen())
	if _, err := io.ReadFull(r, body); err != nil {
		t.Fatal(err)
	}

	if want, got := "hello", string(body); got != want {
		t.Errorf("body: %q != %q", got, want)
	}

	// second frame

	if err := wire.ReadFrameHdr(r, &got); err != nil {
		t.Fatal(err)
	}

	want = wire.FrameHdr{
		Len:  uint32(8 + len("world")),
		Type: 2,
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatal(diff)
	}

	body = make([]byte, got.BodyLen())
	if _, err := io.ReadFull(r, body); err != nil {
		t.Fatal(err)
	}

	if want, got := "world", string(body); got != want {
		t.Errorf("body: %q != %q", got, want)
	}

	if r.Len() > 0 {
		t.Errorf("extra junk: %d", r.Len())
	}
}

func TestReadFrameHdr(t *testing.T) {
	t.Run("short", func(t *testing.T) {
		var h wire.FrameHdr
		if err := wire.ReadFrameHdr(bytes.NewReader(make([]byte, 7)), &h); err == nil {
			t.Error("no error")
		}
	})

	t.Run("short len", func(t *testing.T) {
		// min len is sizeof(FrameHdr), 8
		h := wire.FrameHdr{Len: 7}
		r := bytes.NewReader(h.Encode(nil))

		var hh wire.FrameHdr
		if err := wire.ReadFrameHdr(r, &hh); err == nil {
			t.Error("no error")
		}
	})
}

func TestPingFrameBodyCodec(t *testing.T) {
	want := wire.PingFrameBody{
		ID: 1,
	}

	b := want.Encode(nil)
	b = append(b, "junk"...)

	var got wire.PingFrameBody
	n, err := got.Decode(b)
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatal(diff)
	}

	if want, got := "junk", string(b[n:]); got != want {
		t.Errorf("trailing bytes: %q != %q", got, want)
	}
}

func TestReqFrameBodyCodec(t *testing.T) {
	want := wire.ReqFrameBody{
		ID:   1,
		Data: []byte("data"),
		Path: []byte("path"),
	}

	b := want.Encode(nil)
	b = append(b, "junk"...)

	var got wire.ReqFrameBody
	n, err := got.Decode(b)
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatal(diff)
	}

	if want, got := "junk", string(b[n:]); got != want {
		t.Errorf("trailing bytes: %q != %q", got, want)
	}
}

func TestSubFrameBodyCodec(t *testing.T) {
	want := wire.SubFrameBody{
		ID:    1,
		Limit: 3,
		Path:  []byte("path"),
		Group: []byte("group"),
	}

	b := want.Encode(nil)
	b = append(b, "junk"...)

	var got wire.SubFrameBody
	n, err := got.Decode(b)
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatal(diff)
	}

	if want, got := "junk", string(b[n:]); got != want {
		t.Errorf("trailing bytes: %q != %q", got, want)
	}
}

func TestUnsubFrameBodyCodec(t *testing.T) {
	want := wire.UnsubFrameBody{
		ID: 1,
	}

	b := want.Encode(nil)
	b = append(b, "junk"...)

	var got wire.UnsubFrameBody
	n, err := got.Decode(b)
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatal(diff)
	}

	if want, got := "junk", string(b[n:]); got != want {
		t.Errorf("trailing bytes: %q != %q", got, want)
	}
}

func TestPongFrameBodyCodec(t *testing.T) {
	want := wire.PongFrameBody{
		ID: 1,
	}

	b := want.Encode(nil)
	b = append(b, "junk"...)

	var got wire.PongFrameBody
	n, err := got.Decode(b)
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatal(diff)
	}

	if want, got := "junk", string(b[n:]); got != want {
		t.Errorf("trailing bytes: %q != %q", got, want)
	}
}

func TestPkgFrameBodyCodec(t *testing.T) {
	want := wire.PkgFrameBody{
		ID: 1,
		Msg: wire.Msg{
			Data:  []byte("data"),
			Path:  []byte("path"),
			Reply: []byte("reply"),
		},
	}

	b := want.Encode(nil)
	b = append(b, "junk"...)

	var got wire.PkgFrameBody
	n, err := got.Decode(b)
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatal(diff)
	}

	if want, got := "junk", string(b[n:]); got != want {
		t.Errorf("trailing bytes: %q != %q", got, want)
	}
}

func TestErrFrameBodyCodec(t *testing.T) {
	want := wire.ErrFrameBody{
		ID:    1,
		Errno: 1,
	}

	b := want.Encode(nil)
	b = append(b, "junk"...)

	var got wire.ErrFrameBody
	n, err := got.Decode(b)
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatal(diff)
	}

	if want, got := "junk", string(b[n:]); got != want {
		t.Errorf("trailing bytes: %q != %q", got, want)
	}
}

func TestMsgCodec(t *testing.T) {
	want := wire.Msg{
		Data:  []byte("data"),
		Path:  []byte("path"),
		Reply: []byte("reply"),
	}

	b := want.Encode(nil)
	b = append(b, "junk"...)

	var got wire.Msg
	n, err := got.Decode(b)
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatal(diff)
	}

	if want, got := "junk", string(b[n:]); got != want {
		t.Errorf("trailing bytes: %q != %q", got, want)
	}
}
