package field_test

import (
	"io"
	"testing"

	"yat.io/yat/field"
)

func TestSetRoundtrip(t *testing.T) {
	s := field.Set(nil).AppendValField(1, 1)
	s = s.AppendRunField(2, []byte("hello"))

	s, tag, err := s.ReadTag()
	if err != nil {
		t.Fatal(err)
	}

	if got, want := tag.Field(), 1; got != want {
		t.Errorf("field 0 tag %d != %d", got, want)
	}

	if got, want := tag.Type(), field.Val; got != want {
		t.Errorf("field 0 type %v != %v", got, want)
	}

	s, v, err := s.ReadVal()
	if err != nil {
		t.Fatal(err)
	}

	if got, want := v, uint64(1); got != want {
		t.Errorf("field 0 value %v != %v", got, want)
	}

	s, tag, err = s.ReadTag()
	if err != nil {
		t.Fatal(err)
	}

	if got, want := tag.Field(), 2; got != want {
		t.Errorf("field 1 tag %d != %d", got, want)
	}

	if got, want := tag.Type(), field.Run; got != want {
		t.Errorf("field 1 type %v != %v", got, want)
	}

	s, run, err := s.ReadRun()
	if err != nil {
		t.Fatal(err)
	}

	if got, want := run, []byte("hello"); string(got) != string(want) {
		t.Errorf("field 1 run %q != %q", got, want)
	}

	if len(s) != 0 {
		t.Errorf("leftover bytes in s: %v", s)
	}
}

func TestSet_ReadTag(t *testing.T) {
	t.Run("short", func(t *testing.T) {
		_, _, err := field.Set(nil).ReadTag()
		if err != io.EOF {
			t.Fatal(err)
		}
	})
}

func TestSet_ReadRun(t *testing.T) {
	t.Run("bad-len", func(t *testing.T) {
		s := field.Set(nil).AppendRunField(1, []byte("xx"))
		s, _, err := s[:1].ReadTag()
		if err != nil {
			t.Fatal(err)
		}

		if _, _, err = s.ReadRun(); err == nil {
			t.Fatal("no error")
		}
	})

	t.Run("short", func(t *testing.T) {
		s := field.Set(nil).AppendRunField(1, []byte("xx"))
		s, _, err := s.ReadTag()
		if err != nil {
			t.Fatal(err)
		}

		if _, _, err = s[:len(s)-1].ReadRun(); err == nil {
			t.Fatal("no error")
		}
	})
}

func TestSet_Discard(t *testing.T) {
	good := map[string]field.Set{
		"value": field.Set(nil).AppendValField(1, 1),
		"run":   field.Set(nil).AppendRunField(2, []byte("x")),
	}

	for name, s := range good {
		t.Run(name, func(t *testing.T) {
			s, tag, err := s.ReadTag()
			if err != nil {
				t.Fatal(err)
			}

			s, err = s.Discard(tag)
			if err != nil {
				t.Fatal(err)
			}

			if len(s) != 0 {
				t.Errorf("leftover bytes in s: %v", s)
			}
		})
	}

	for name, s := range good {
		t.Run("short-"+name, func(t *testing.T) {
			s = s[:len(s)-1]
			s, tag, err := s.ReadTag()
			if err != nil {
				t.Fatal(err)
			}

			if _, err := s.Discard(tag); err == nil {
				t.Fatal("no error")
			}
		})
	}
}

func TestType_String(t *testing.T) {
	tcs := []struct {
		Type field.Type
		Want string
	}{
		{field.Val, "Value"},
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
