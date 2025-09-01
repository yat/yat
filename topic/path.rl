package topic

import (
	"errors"
	"math"
)

%%{
	machine path;
	alphtype byte;

	action wildcard {
		wild = true
	}

	star  = "*" %wildcard;
	suf   = "**" %wildcard;
	seg   = [^\0/*]+ | star;
	main := suf | (seg ("/" seg)* ("/" suf)?);
}%%

%% write data;

// Parse parses a topic path from a raw value.
// If the value is a byte slice, the returned path aliases the slice.
// Parse returns an error if the path is invalid.
// If the path contains a * or ** segment, Parse returns wild=true.
func Parse[V ~[]byte | ~string](raw V) (parsed Path, wild bool, err error) {
	if len(raw) == 0 {
		return
	}

	data := []byte(raw)
	if len(data) > math.MaxUint16 {
		err = errors.New("long topic path")
		return
	}

	var (
		_   = path_error
		_   = path_en_main
		cs  = 0
		p   = 0
		pe  = len(data)
		eof = pe
	)

	%% write init;
	%% write exec;

	if cs < path_first_final {
		err = errors.New("invalid topic path")
		return
	}

  parsed = Path{data}
	return
}
