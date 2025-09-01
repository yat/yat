package nv_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"testing"

	"github.com/yat/yat/internal/nv"
)

func TestAppendPutParse_RoundTrip(t *testing.T) {
	vals := []uint64{
		0, 1, 2, 7, 8, 15, 16, 63, 64, 65, 126, 127,
		128, 129, 255, 256,
		0xFFFF, 0x10000,
		0xFFFFFF, 0x1000000,
		0xFFFFFFFF, 0x100000000,
		0xFFFFFFFFFFFF, 0x1000000000000,
		0xFFFFFFFFFFFFFF, 0x100000000000000,
		0xFFFFFFFFFFFFFFFF,
	}

	for _, v := range vals {
		t.Run(fmt.Sprintf("v=%#x", v), func(t *testing.T) {
			got := nv.Append(nil, v)

			// Len check
			if len(got) != nv.Len(v) {
				t.Fatalf("len(Append(%#x))=%d, want %d", v, len(got), nv.Len(v))
			}

			// Put equality
			buf := make([]byte, nv.Len(v))
			n := nv.Put(buf, v)
			if n != len(got) {
				t.Fatalf("Put wrote %d bytes, want %d", n, len(got))
			}
			if !bytes.Equal(got, buf) {
				t.Fatalf("Append vs Put mismatch:\n got % x\nwant % x", got, buf)
			}

			// Parse round-trip
			pv, pn := nv.Parse(got)
			if pn != len(got) {
				t.Fatalf("Parse consumed %d, want %d", pn, len(got))
			}
			if pv != v {
				t.Fatalf("Parse value %#x, want %#x", pv, v)
			}
		})
	}
}

func TestStreamDecode(t *testing.T) {
	vv := []uint64{
		0, 1, 127, 128, 255, 256,
		0xFFFFFF, 0x1000000,
		0xFFFFFFFFFFFFFFFF,
	}
	var stream []byte
	for _, v := range vv {
		stream = nv.Append(stream, v)
	}
	off := 0
	for i, want := range vv {
		got, n := nv.Parse(stream[off:])
		if n <= 0 {
			t.Fatalf("Parse failed at index %d, off=%d: n=%d", i, off, n)
		}
		if got != want {
			t.Fatalf("value[%d]=%#x, want %#x", i, got, want)
		}
		off += n
	}
	if off != len(stream) {
		t.Fatalf("did not consume entire stream: off=%d len=%d", off, len(stream))
	}
}

func TestParseIncomplete(t *testing.T) {
	// Header says nb=2 (low bits=1), but only 1 payload byte present.
	b := []byte{0x80 | 0x01, 0xAA} // need 3 bytes total; have 2
	_, n := nv.Parse(b)
	if n != 0 {
		t.Fatalf("incomplete buffer: n=%d, want 0", n)
	}

	// Zero-length buffer.
	_, n = nv.Parse(nil)
	if n != 0 {
		t.Fatalf("nil buffer: n=%d, want 0", n)
	}
}

func TestNonCanonicalAccepted(t *testing.T) {
	// Value 5 encoded with prefixed nb=1 (non-minimal but should decode).
	b := []byte{0x80, 0x05}
	v, n := nv.Parse(b)
	if v != 5 || n != 2 {
		t.Fatalf("non-canonical nb=1: got (v=%d,n=%d), want (5,2)", v, n)
	}
	// Value 5 encoded with prefixed nb=2 and a zero high byte (also non-minimal).
	b = []byte{0x80 | 0x01, 0x05, 0x00}
	v, n = nv.Parse(b)
	if v != 5 || n != 3 {
		t.Fatalf("non-canonical nb=2: got (v=%d,n=%d), want (5,3)", v, n)
	}
}

func TestPutPanicsWhenTooSmall(t *testing.T) {
	t.Run("empty buffer", func(t *testing.T) {
		defer mustPanic(t)
		var b []byte // len==0
		nv.Put(b, 1) // needs 1 byte
	})
	t.Run("short payload", func(t *testing.T) {
		defer mustPanic(t)
		b := make([]byte, 1) // header only
		nv.Put(b, 256)       // header ok, payload write should panic
	})
}

func TestLenBoundaries(t *testing.T) {
	// For k>=1, max value that still fits in k payload bytes: (1<<(8*k))-1.
	for k := 1; k <= 8; k++ {
		maxK := (uint64(1) << (8 * k)) - 1
		minNext := uint64(1) << (8 * k) // uses k+1 payload bytes (unless k==8)

		t.Run(fmt.Sprintf("maxK_%dB", k), func(t *testing.T) {
			enc := nv.Append(nil, maxK)
			wantLen := nv.Len(maxK)
			if len(enc) != wantLen {
				t.Fatalf("len(enc(maxK))=%d, want %d", len(enc), wantLen)
			}
			if v, n := nv.Parse(enc); v != maxK || n != len(enc) {
				t.Fatalf("round-trip maxK failed: v=%#x n=%d", v, n)
			}
		})

		if k < 8 {
			t.Run(fmt.Sprintf("minNext_%dB", k+1), func(t *testing.T) {
				enc := nv.Append(nil, minNext)
				wantLen := nv.Len(minNext)
				if len(enc) != wantLen {
					t.Fatalf("len(enc(minNext))=%d, want %d", len(enc), wantLen)
				}
				if v, n := nv.Parse(enc); v != minNext || n != len(enc) {
					t.Fatalf("round-trip minNext failed: v=%#x n=%d", v, n)
				}
			})
		}
	}
}

// --- helpers ---

func mustPanic(t *testing.T) {
	t.Helper()
	if r := recover(); r == nil {
		t.Fatalf("expected panic, got none")
	}
}

func BenchmarkPut(b *testing.B) {
	buf := make([]byte, 10)
	val := uint64(math.MaxUint64)

	b.Run("uvarint", func(b *testing.B) {
		for b.Loop() {
			if n := binary.PutUvarint(buf, val); n != 10 {
				b.Fatal(n)
			}
		}
	})

	b.Run("nv", func(b *testing.B) {
		for b.Loop() {
			if n := nv.Put(buf, val); n != 9 {
				b.Fatal(n)
			}
		}
	})
}

func BenchmarkParse(b *testing.B) {
	want := uint64(math.MaxUint64)
	ubuf := binary.AppendUvarint(nil, want)
	nvbuf := nv.Append(nil, want)

	b.Run("uvarint", func(b *testing.B) {
		for b.Loop() {
			value, n := binary.Uvarint(ubuf)
			if n <= 0 {
				b.Fatal(n)
			}

			if value != want {
				b.Fatal("value", value)
			}
		}
	})

	b.Run("nv", func(b *testing.B) {
		for b.Loop() {
			value, n := nv.Parse(nvbuf)
			if n <= 0 {
				b.Fatal(n)
			}

			if value != want {
				b.Fatal("value", value)
			}
		}
	})
}
