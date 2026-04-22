//go:build !human

package yat

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

// Only add a test here if it exercises a failure branch
// that is impossible to reach with an integration test.
//
// These tests aren't really here to define behavior,
// think of them more like the output of a fuzzer.
// Humans don't really read these.

func TestInternalParseMsgPubFrmCleanFrame(t *testing.T) {
	frm := appendGRPCFrm(nil, func(b []byte) []byte {
		b = protowire.AppendTag(b, 99, protowire.VarintType)
		b = protowire.AppendVarint(b, 1)
		b = protowire.AppendTag(b, ackField, protowire.VarintType)
		b = protowire.AppendVarint(b, 42)
		b = protowire.AppendTag(b, pathField, protowire.BytesType)
		b = protowire.AppendString(b, "pub/topic")
		b = protowire.AppendTag(b, pathField, protowire.BytesType)
		b = protowire.AppendString(b, "ignored/path")
		b = protowire.AppendTag(b, inboxField, protowire.BytesType)
		b = protowire.AppendString(b, "reply/topic")
		b = protowire.AppendTag(b, dataField, protowire.BytesType)
		b = protowire.AppendBytes(b, []byte("payload"))
		b = protowire.AppendTag(b, 100, protowire.BytesType)
		b = protowire.AppendString(b, "ignored")
		return b
	})

	clean, fields, err := parseMsgPubFrm(frm)
	if err != nil {
		t.Fatal(err)
	}

	want := appendGRPCFrm(nil, func(b []byte) []byte {
		b = protowire.AppendTag(b, pathField, protowire.BytesType)
		b = protowire.AppendString(b, "pub/topic")
		b = protowire.AppendTag(b, inboxField, protowire.BytesType)
		b = protowire.AppendString(b, "reply/topic")
		b = protowire.AppendTag(b, dataField, protowire.BytesType)
		b = protowire.AppendBytes(b, []byte("payload"))
		return b
	})

	if !bytes.Equal(clean, want) {
		t.Fatalf("clean frame = %x, want %x", clean, want)
	}
	if fields.Ack != 42 {
		t.Fatalf("ack = %d, want 42", fields.Ack)
	}

	msg, err := fields.Parse()
	if err != nil {
		t.Fatal(err)
	}
	if !msg.Path.Equal(NewPath("pub/topic")) ||
		!msg.Inbox.Equal(NewPath("reply/topic")) ||
		!bytes.Equal(msg.Data, []byte("payload")) {
		t.Fatalf("msg = %+v", msg)
	}
}

func TestInternalParseMsgPostFrmCleanFrame(t *testing.T) {
	frm := appendGRPCFrm(nil, func(b []byte) []byte {
		b = protowire.AppendTag(b, 99, protowire.VarintType)
		b = protowire.AppendVarint(b, 1)
		b = protowire.AppendTag(b, limitField, protowire.VarintType)
		b = protowire.AppendVarint(b, 3)
		b = protowire.AppendTag(b, pathField, protowire.BytesType)
		b = protowire.AppendString(b, "post/topic")
		b = protowire.AppendTag(b, pathField, protowire.BytesType)
		b = protowire.AppendString(b, "ignored/path")
		b = protowire.AppendTag(b, dataField, protowire.BytesType)
		b = protowire.AppendBytes(b, []byte("request"))
		b = protowire.AppendTag(b, 100, protowire.BytesType)
		b = protowire.AppendString(b, "ignored")
		return b
	})

	clean, fields, err := parseMsgPostFrm(frm)
	if err != nil {
		t.Fatal(err)
	}

	want := appendGRPCFrm(nil, func(b []byte) []byte {
		b = protowire.AppendTag(b, pathField, protowire.BytesType)
		b = protowire.AppendString(b, "post/topic")
		b = protowire.AppendTag(b, dataField, protowire.BytesType)
		b = protowire.AppendBytes(b, []byte("request"))
		return b
	})

	if !bytes.Equal(clean, want) {
		t.Fatalf("clean frame = %x, want %x", clean, want)
	}
	if fields.Limit != 3 {
		t.Fatalf("limit = %d, want 3", fields.Limit)
	}

	path, data, err := fields.Parse()
	if err != nil {
		t.Fatal(err)
	}
	if !path.Equal(NewPath("post/topic")) || !bytes.Equal(data, []byte("request")) {
		t.Fatalf("path=%q data=%q", path.String(), data)
	}
}

func TestInternalRouterValidPostboxRejectsMalformedTokens(t *testing.T) {
	router := NewRouter()

	valid := router.newPostbox()
	if !router.validPostbox(valid) {
		t.Fatal("fresh postbox is invalid")
	}

	foreign := NewRouter().newPostbox()
	if router.validPostbox(foreign) {
		t.Fatal("foreign postbox is valid")
	}

	tampered := []byte(valid.s)
	slash := bytes.IndexByte(tampered, '/')
	if slash < 0 || slash+1 >= len(tampered) {
		t.Fatalf("postbox %q has no token", valid.s)
	}
	if tampered[slash+1] == 'A' {
		tampered[slash+1] = 'B'
	} else {
		tampered[slash+1] = 'A'
	}

	cases := []Path{
		{},
		{s: "topic"},
		{s: "@"},
		{s: "@!/x"},
		{s: "@" + base64.RawURLEncoding.EncodeToString(router.id[:]) + "/!"},
		{s: "@" + base64.RawURLEncoding.EncodeToString(router.id[:]) + "/" + base64.RawURLEncoding.EncodeToString([]byte("short"))},
		{s: string(tampered)},
		expiredPostbox(router),
	}

	for _, tc := range cases {
		if router.validPostbox(tc) {
			t.Fatalf("postbox %q is valid", tc.s)
		}
	}
}

func TestInternalRnodePrunesWildcardCaches(t *testing.T) {
	var root rnode
	noop := func(rmsg, bool) {}

	elem := root.Ins(rsub{Sel: Sel{Path: NewPath("*")}}, noop)
	if root.wildElem == nil {
		t.Fatal("wild element cache was not set")
	}
	elem.up.Del(elem)
	elem.up.Del(elem)
	if root.wildElem != nil {
		t.Fatal("wild element cache was not pruned")
	}
	if leaf := root.leaf(NewPath("*"), false); leaf != nil {
		t.Fatalf("leaf(*, false) = %p, want nil", leaf)
	}

	suffix := root.Ins(rsub{Sel: Sel{Path: NewPath("**")}}, noop)
	if root.wildSuffix == nil {
		t.Fatal("wild suffix cache was not set")
	}
	suffix.up.Del(suffix)
	if root.wildSuffix != nil {
		t.Fatal("wild suffix cache was not pruned")
	}

	nested := root.Ins(rsub{Sel: Sel{Path: NewPath("prefix/**")}}, noop)
	prefix := root.dn["prefix"]
	if prefix == nil || prefix.wildSuffix == nil {
		t.Fatal("nested wild suffix cache was not set")
	}
	nested.up.Del(nested)
	if root.dn["prefix"] != nil {
		t.Fatal("nested wild suffix branch was not pruned")
	}
}

func expiredPostbox(r *Router) Path {
	var tok [32]byte
	binary.LittleEndian.PutUint64(tok[8:16],
		uint64(time.Now().Add(-time.Second).Unix()))

	mac := hmac.New(sha256.New, r.pk[:])
	_, _ = mac.Write(tok[:16])
	copy(tok[16:], mac.Sum(nil))

	return Path{s: "@" +
		base64.RawURLEncoding.EncodeToString(r.id[:]) +
		"/" +
		base64.RawURLEncoding.EncodeToString(tok[:])}
}
