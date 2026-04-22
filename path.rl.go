//line path.rl:1
package yat

import "errors"

//line path.rl:13

//line path.rl.go:13
const path_start int = 1
const path_first_final int = 2
const path_error int = 0

const path_en_main int = 1

//line path.rl:16

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
		_  = path_error
		_  = path_en_main
		cs = 0
		p  = 0
		pe = len(data)
	)

//line path.rl.go:46
	{
		cs = path_start
	}

//line path.rl:40

//line path.rl.go:53
	{
		if p == pe {
			goto _test_eof
		}
		switch cs {
		case 1:
			goto st_case_1
		case 0:
			goto st_case_0
		case 2:
			goto st_case_2
		case 3:
			goto st_case_3
		case 4:
			goto st_case_4
		}
		goto st_out
	st1:
		if p++; p == pe {
			goto _test_eof1
		}
	st_case_1:
		switch data[p] {
		case 0:
			goto st0
		case 42:
			goto st3
		case 47:
			goto st0
		}
		goto st2
	st_case_0:
	st0:
		cs = 0
		goto _out
	st2:
		if p++; p == pe {
			goto _test_eof2
		}
	st_case_2:
		switch data[p] {
		case 0:
			goto st0
		case 42:
			goto st0
		case 47:
			goto st1
		}
		goto st2
	st3:
		if p++; p == pe {
			goto _test_eof3
		}
	st_case_3:
		switch data[p] {
		case 42:
			goto st4
		case 47:
			goto st1
		}
		goto st0
	st4:
		if p++; p == pe {
			goto _test_eof4
		}
	st_case_4:
		goto st0
	st_out:
	_test_eof1:
		cs = 1
		goto _test_eof
	_test_eof2:
		cs = 2
		goto _test_eof
	_test_eof3:
		cs = 3
		goto _test_eof
	_test_eof4:
		cs = 4
		goto _test_eof

	_test_eof:
		{
		}
	_out:
		{
		}
	}

//line path.rl:41

	if cs < path_first_final {
		err = errors.New("invalid path")
		return
	}

	parsed = unsafePath(data)
	return
}
