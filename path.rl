package yat

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

func parsePath[V ~[]byte | ~string](raw V) (parsed Path, wild bool, err error) {
	if len(raw) == 0 {
		return
	}

	data := []byte(raw)
	if len(data) > math.MaxUint16 {
		err = errors.New("long path")
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
		err = errors.New("invalid path")
		return
	}

  parsed = Path{data}
	return
}
