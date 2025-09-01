package field_test

import (
	"io"
	"testing"

	"github.com/yat/yat/internal/field"
	"github.com/yat/yat/internal/nv"
)

func TestReader(t *testing.T) {
	var b []byte
	b = field.AppendTag(b, field.Num, 1)
	b = nv.Append(b, 1111)

	var r field.Reader
	r.Reset(b)

	tag, err := r.ReadTag()
	if err != nil {
		t.Fatal(err)
	}

	if got, want := tag.Type(), field.Num; got != want {
		t.Errorf("type %v != %v", got, want)
	}

	if got, want := tag.Field(), 1; got != want {
		t.Errorf("field number %d != %d", got, want)
	}

	value, err := r.ReadNum()
	if err != nil {
		t.Fatal(err)
	}

	if got, want := value, uint64(1111); got != want {
		t.Errorf("value %d != %d", got, want)
	}

	_, err = r.ReadTag()
	if got, want := err, io.EOF; got != want {
		t.Errorf("after exhausting the set, read returned %v, not %v", got, want)
	}
}
