package yat

import "errors"

%%{
	machine path;
	alphtype byte;

	star  = "*";
	suf   = "**";
	seg   = [^\0/*]+ | star;
	main := suf | (seg ("/" seg)* ("/" suf)?);
}%%

%% write data;

// ParsePath parses a path from a buffer.
// The returned path is a view into the buffer.
func ParsePath[V ~[]byte | ~string](raw V) (parsed Path, err error) {
	if len(raw) == 0 {
		err = errors.New("short path")
		return
	}

	data := []byte(raw)
	if len(data) > MaxPathLen {
		err = errors.New("long path")
		return
	}

	var (
		_   = path_error
		_   = path_en_main
		cs  = 0
		p   = 0
		pe  = len(data)
	)

	%% write init;
	%% write exec;

	if cs < path_first_final {
		err = errors.New("invalid path")
		return
	}

	parsed = unsafePath(data)
	return
}
