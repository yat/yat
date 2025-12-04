package yat

import (
	"context"
	"errors"
	"fmt"
)

type Publisher interface {
	Publish(Msg) error
}

type Subscriber interface {
	Subscribe(Sel, func(Msg)) (Sub, error)
}

type Requester interface {
	Request(ctx context.Context, path Path, data []byte, f func(Msg) error) error
}

type Sel struct {
	Limit int
	Path  Path
	Group Group
}

type Sub interface {
	Stop()                 // stops the subscription
	Done() <-chan struct{} // closed after the sub stops
}

// Errno identifies a particular Yat error.
type Errno uint32

const (
	ENOENT = Errno(2)  // no subscribers
	EINVAL = Errno(22) // invalid argument
)

var (
	errLongFrame     = errors.New("long frame")
	errMissingPath   = errors.New("missing message path")
	errNegativeLimit = errors.New("negative limit")
)

func (e Errno) Error() string {
	switch e {
	case ENOENT:
		return "no subscribers"

	case EINVAL:
		return "invalid argument"

	default:
		return e.String()
	}
}

func (e Errno) String() string {
	switch e {
	case ENOENT:
		return "ENOENT"

	case EINVAL:
		return "EINVAL"

	default:
		return fmt.Sprintf("Errno(%d)", e)
	}
}
