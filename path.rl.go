//line path.rl:1
package yat

import (
	"errors"
	"math"
)

//line path.rl:20

//line path.rl.go:16
const path_start int = 1
const path_first_final int = 2
const path_error int = 0

const path_en_main int = 1

//line path.rl:23

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

//line path.rl.go:47
	{
		cs = path_start
	}

//line path.rl:45

//line path.rl.go:54
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
	tr5:
//line path.rl:12

		wild = true

		goto st1
	st1:
		if p++; p == pe {
			goto _test_eof1
		}
	st_case_1:
//line path.rl.go:83
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
			goto tr5
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
		if p == eof {
			switch cs {
			case 3, 4:
//line path.rl:12

				wild = true

//line path.rl.go:143
			}
		}

	_out:
		{
		}
	}

//line path.rl:46

	if cs < path_first_final {
		err = errors.New("invalid path")
		return
	}

	parsed = Path{data}
	return
}
