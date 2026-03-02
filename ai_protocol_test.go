package yat

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
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

func Test_appendFrameBytes(t *testing.T) {
	prefix := []byte{0xaa, 0xbb}
	body := []byte("jwt")

	got := appendFrameBytes(bytes.Clone(prefix), jwtFrameType, body)
	want := appendFrame(bytes.Clone(prefix), jwtFrameType, func(b []byte) []byte {
		return append(b, body...)
	})

	if !bytes.Equal(got, want) {
		t.Fatalf("frame: %x != %x", got, want)
	}
}

func Test_parsePubFrame(t *testing.T) {
	t.Run("parses and compacts known fields", func(t *testing.T) {
		buf := make([]byte, 0, 64)
		buf = protowire.AppendTag(buf, 99, protowire.VarintType)
		buf = protowire.AppendVarint(buf, 1)
		buf = protowire.AppendTag(buf, pathField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("a/b"))
		buf = protowire.AppendTag(buf, 98, protowire.Fixed32Type)
		buf = protowire.AppendFixed32(buf, 7)
		buf = protowire.AppendTag(buf, dataField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("payload"))
		buf = protowire.AppendTag(buf, inboxField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("inbox"))
		buf = protowire.AppendTag(buf, 97, protowire.VarintType)
		buf = protowire.AppendVarint(buf, 2)

		_, msg, raw, err := parseMsg(buf)
		if err != nil {
			t.Fatal(err)
		}

		want := make([]byte, 0, len(raw))
		want = protowire.AppendTag(want, pathField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte("a/b"))
		want = protowire.AppendTag(want, dataField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte("payload"))
		want = protowire.AppendTag(want, inboxField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte("inbox"))

		if !bytes.Equal(raw, want) {
			t.Fatalf("compact mismatch: %x != %x", raw, want)
		}
		if len(raw) > 0 && &raw[0] != &buf[0] {
			t.Fatal("raw does not alias body prefix")
		}
		if got := msg.Path.String(); got != "a/b" {
			t.Fatalf("path: %q != %q", got, "a/b")
		}
		if !bytes.Equal(msg.Data, []byte("payload")) {
			t.Fatalf("data: %q != %q", msg.Data, "payload")
		}
		if got := msg.Inbox.String(); got != "inbox" {
			t.Fatalf("inbox: %q != %q", got, "inbox")
		}
	})

	t.Run("extracts num and omits it from compacted raw", func(t *testing.T) {
		buf := make([]byte, 0, 64)
		buf = protowire.AppendTag(buf, numField, protowire.VarintType)
		buf = protowire.AppendVarint(buf, 42)
		buf = protowire.AppendTag(buf, pathField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("a/b"))
		buf = protowire.AppendTag(buf, dataField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("payload"))

		num, msg, raw, err := parseMsg(buf)
		if err != nil {
			t.Fatal(err)
		}
		if num != 42 {
			t.Fatalf("num: %d != %d", num, 42)
		}

		want := make([]byte, 0, len(raw))
		want = protowire.AppendTag(want, pathField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte("a/b"))
		want = protowire.AppendTag(want, dataField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte("payload"))
		if !bytes.Equal(raw, want) {
			t.Fatalf("compact mismatch: %x != %x", raw, want)
		}
		if got := msg.Path.String(); got != "a/b" {
			t.Fatalf("path: %q != %q", got, "a/b")
		}
		if !bytes.Equal(msg.Data, []byte("payload")) {
			t.Fatalf("data: %q != %q", msg.Data, "payload")
		}
	})

	t.Run("repeated fields last wins", func(t *testing.T) {
		buf := make([]byte, 0, 64)
		buf = protowire.AppendTag(buf, pathField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("a"))
		buf = protowire.AppendTag(buf, dataField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("v1"))
		buf = protowire.AppendTag(buf, pathField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("b/c"))
		buf = protowire.AppendTag(buf, dataField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("v2"))
		buf = protowire.AppendTag(buf, inboxField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("r"))

		_, msg, raw, err := parseMsg(buf)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) == 0 {
			t.Fatal("empty raw")
		}
		if got := msg.Path.String(); got != "b/c" {
			t.Fatalf("path: %q != %q", got, "b/c")
		}
		if !bytes.Equal(msg.Data, []byte("v2")) {
			t.Fatalf("data: %q != %q", msg.Data, "v2")
		}
		if got := msg.Inbox.String(); got != "r" {
			t.Fatalf("inbox: %q != %q", got, "r")
		}
	})

	t.Run("unknown-only frame", func(t *testing.T) {
		buf := make([]byte, 0, 16)
		buf = protowire.AppendTag(buf, 99, protowire.VarintType)
		buf = protowire.AppendVarint(buf, 7)
		buf = protowire.AppendTag(buf, 98, protowire.Fixed32Type)
		buf = protowire.AppendFixed32(buf, 1)

		_, msg, raw, err := parseMsg(buf)
		if !errors.Is(err, errEmptyPath) {
			t.Fatalf("error: %v", err)
		}
		if len(raw) != 0 {
			t.Fatalf("len: %d != 0", len(raw))
		}
		if !msg.Path.IsZero() || len(msg.Data) != 0 || !msg.Inbox.IsZero() {
			t.Fatal("non-zero msg")
		}
	})

	t.Run("malformed tag with no accepted fields", func(t *testing.T) {
		buf := []byte{0x80}

		_, msg, raw, err := parseMsg(buf)
		if err == nil {
			t.Fatal("expected error")
		}
		if len(raw) != 0 {
			t.Fatalf("len: %d != 0", len(raw))
		}
		if !msg.Path.IsZero() || len(msg.Data) != 0 || !msg.Inbox.IsZero() {
			t.Fatal("non-zero msg")
		}
	})

	t.Run("wrong type with no accepted fields", func(t *testing.T) {
		buf := make([]byte, 0, 8)
		buf = protowire.AppendTag(buf, pathField, protowire.VarintType)
		buf = protowire.AppendVarint(buf, 1)

		_, msg, raw, err := parseMsg(buf)
		if err == nil {
			t.Fatal("expected error")
		}
		if len(raw) != 0 {
			t.Fatalf("len: %d != 0", len(raw))
		}
		if !msg.Path.IsZero() || len(msg.Data) != 0 || !msg.Inbox.IsZero() {
			t.Fatal("non-zero msg")
		}
	})

	t.Run("malformed known field keeps accepted prefix", func(t *testing.T) {
		buf := make([]byte, 0, 16)
		buf = protowire.AppendTag(buf, pathField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("ok"))
		buf = protowire.AppendTag(buf, dataField, protowire.BytesType)
		buf = protowire.AppendVarint(buf, 5)
		buf = append(buf, 'x')

		_, msg, raw, err := parseMsg(buf)
		if err == nil {
			t.Fatal("expected error")
		}
		want := make([]byte, 0, len(raw))
		want = protowire.AppendTag(want, pathField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte("ok"))
		if !bytes.Equal(raw, want) {
			t.Fatalf("raw: %x != %x", raw, want)
		}
		if !msg.Path.IsZero() || len(msg.Data) != 0 || !msg.Inbox.IsZero() {
			t.Fatal("non-zero msg")
		}
	})

	t.Run("invalid path keeps compacted raw", func(t *testing.T) {
		buf := make([]byte, 0, 16)
		buf = protowire.AppendTag(buf, pathField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte{})

		_, msg, raw, err := parseMsg(buf)
		if err == nil {
			t.Fatal("expected error")
		}
		want := make([]byte, 0, len(raw))
		want = protowire.AppendTag(want, pathField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte{})
		if !bytes.Equal(raw, want) {
			t.Fatalf("raw: %x != %x", raw, want)
		}
		if !msg.Path.IsZero() || len(msg.Data) != 0 || !msg.Inbox.IsZero() {
			t.Fatal("non-zero msg")
		}
	})

	t.Run("wild path keeps compacted raw", func(t *testing.T) {
		buf := make([]byte, 0, 16)
		buf = protowire.AppendTag(buf, pathField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("*"))

		_, _, raw, err := parseMsg(buf)
		if !errors.Is(err, errWildPath) {
			t.Fatalf("error: %v", err)
		}
		want := make([]byte, 0, len(raw))
		want = protowire.AppendTag(want, pathField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte("*"))
		if !bytes.Equal(raw, want) {
			t.Fatalf("raw: %x != %x", raw, want)
		}
	})

	t.Run("invalid inbox keeps compacted raw", func(t *testing.T) {
		buf := make([]byte, 0, 24)
		buf = protowire.AppendTag(buf, pathField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("ok"))
		buf = protowire.AppendTag(buf, inboxField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte{})

		_, msg, raw, err := parseMsg(buf)
		if err == nil {
			t.Fatal("expected error")
		}
		want := make([]byte, 0, len(raw))
		want = protowire.AppendTag(want, pathField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte("ok"))
		want = protowire.AppendTag(want, inboxField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte{})
		if !bytes.Equal(raw, want) {
			t.Fatalf("raw: %x != %x", raw, want)
		}
		if got := msg.Path.String(); got != "ok" {
			t.Fatalf("path: %q != %q", got, "ok")
		}
	})

	t.Run("wild inbox keeps compacted raw", func(t *testing.T) {
		buf := make([]byte, 0, 24)
		buf = protowire.AppendTag(buf, pathField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("ok"))
		buf = protowire.AppendTag(buf, inboxField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("*"))

		_, msg, raw, err := parseMsg(buf)
		if !errors.Is(err, errWildInbox) {
			t.Fatalf("error: %v", err)
		}
		want := make([]byte, 0, len(raw))
		want = protowire.AppendTag(want, pathField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte("ok"))
		want = protowire.AppendTag(want, inboxField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte("*"))
		if !bytes.Equal(raw, want) {
			t.Fatalf("raw: %x != %x", raw, want)
		}
		if got := msg.Path.String(); got != "ok" {
			t.Fatalf("path: %q != %q", got, "ok")
		}
	})

	t.Run("malformed unknown field with no accepted fields", func(t *testing.T) {
		buf := make([]byte, 0, 16)
		buf = protowire.AppendTag(buf, 99, protowire.BytesType)
		buf = protowire.AppendVarint(buf, 3)
		buf = append(buf, 'x')

		_, msg, raw, err := parseMsg(buf)
		if err == nil {
			t.Fatal("expected error")
		}
		if len(raw) != 0 {
			t.Fatalf("len: %d != 0", len(raw))
		}
		if !msg.Path.IsZero() || len(msg.Data) != 0 || !msg.Inbox.IsZero() {
			t.Fatal("non-zero msg")
		}
	})

	t.Run("num field with wrong type keeps accepted prefix", func(t *testing.T) {
		buf := make([]byte, 0, 24)
		buf = protowire.AppendTag(buf, pathField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("ok"))
		buf = protowire.AppendTag(buf, numField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("not-varint"))

		_, msg, raw, err := parseMsg(buf)
		if err == nil {
			t.Fatal("expected error")
		}

		want := make([]byte, 0, len(raw))
		want = protowire.AppendTag(want, pathField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte("ok"))
		if !bytes.Equal(raw, want) {
			t.Fatalf("raw: %x != %x", raw, want)
		}
		if !msg.Path.IsZero() || len(msg.Data) != 0 || !msg.Inbox.IsZero() {
			t.Fatal("non-zero msg")
		}
	})

	t.Run("malformed num varint keeps accepted prefix", func(t *testing.T) {
		buf := make([]byte, 0, 24)
		buf = protowire.AppendTag(buf, pathField, protowire.BytesType)
		buf = protowire.AppendBytes(buf, []byte("ok"))
		buf = protowire.AppendTag(buf, numField, protowire.VarintType)
		buf = append(buf, 0x80) // truncated varint

		_, msg, raw, err := parseMsg(buf)
		if err == nil {
			t.Fatal("expected error")
		}

		want := make([]byte, 0, len(raw))
		want = protowire.AppendTag(want, pathField, protowire.BytesType)
		want = protowire.AppendBytes(want, []byte("ok"))
		if !bytes.Equal(raw, want) {
			t.Fatalf("raw: %x != %x", raw, want)
		}
		if !msg.Path.IsZero() || len(msg.Data) != 0 || !msg.Inbox.IsZero() {
			t.Fatal("non-zero msg")
		}
	})
}
