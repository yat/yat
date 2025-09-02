package field_test

import (
	"encoding/binary"
	"fmt"
	"testing"

	"yat.io/field"
)

func TestAppendTag(t *testing.T) {
	tcs := []struct {
		Type  field.Type
		Field int
	}{
		{field.Num, 1},
		{field.Run, 2},
	}

	for _, tc := range tcs {
		t.Run(fmt.Sprintf("%v-%v", tc.Type, tc.Field), func(t *testing.T) {
			b := field.AppendTag(nil, tc.Type, tc.Field)
			tag := field.Tag(b[0])

			if got := tag.Type(); got != tc.Type {
				t.Errorf("type %v != %v", got, tc.Type)
			}

			if got := tag.Field(); got != tc.Field {
				t.Errorf("field number %d != %d", got, tc.Field)
			}
		})
	}
}

func TestAppendTag_TruncateField(t *testing.T) {
	tcs := []struct {
		Field int // out-of-range field number
		Want  int // truncated field number
	}{
		{129, 1},
		{-1, 127},
	}

	for _, tc := range tcs {
		t.Run(fmt.Sprint(tc.Field), func(t *testing.T) {
			b := field.AppendTag(nil, 0, tc.Field)
			tag := field.Tag(b[0])

			if got := tag.Field(); got != tc.Want {
				t.Errorf("truncating %d: %d != %d", tc.Field, got, tc.Want)
			}
		})
	}
}

func TestAppendRun(t *testing.T) {
	want := "hello"
	b := field.AppendRun(nil, want)
	rlen, n := binary.Uvarint(b)
	if n <= 0 {
		t.Fatal()
	}

	if got, want := rlen, uint64(len(want)); got != want {
		t.Errorf("decoded len %d != %d", got, want)
	}

	if got := string(b[n:]); got != want {
		t.Errorf("decoded run %q != %q", got, want)
	}
}

func TestType_String(t *testing.T) {
	tcs := []struct {
		Type field.Type
		Want string
	}{
		{field.Num, "Num"},
		{field.Run, "Run"},
		{99, "Type(99)"},
	}

	for _, tc := range tcs {
		t.Run(tc.Want, func(t *testing.T) {
			if got, want := tc.Type.String(), tc.Want; got != want {
				t.Errorf("type string %v != %v", got, want)
			}
		})
	}
}
