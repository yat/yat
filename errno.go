package yat

import (
	"fmt"
)

// Errno is the set of request/response errors.
type Errno uint64

const (
	EPERM  = Errno(1)  // permission denied
	ENOENT = Errno(2)  // responder not found
	EIO    = Errno(5)  // input/output error
	EINVAL = Errno(22) // invalid argument
)

// Error returns a description of the errno.
func (e Errno) Error() string {
	switch e {
	case EPERM:
		return "permission denied"

	case ENOENT:
		return "responder not found"

	case EIO:
		return "input/output"

	case EINVAL:
		return "invalid argument"

	default:
		return e.String()
	}
}

// String returns the name of the errno
// or "errno(value)" if the value is unknown.
func (e Errno) String() string {
	switch e {
	case EPERM:
		return "EPERM"

	case ENOENT:
		return "ENOENT"

	case EIO:
		return "EIO"

	case EINVAL:
		return "EINVAL"

	default:
		return fmt.Sprintf("errno(%d)", e)
	}
}
