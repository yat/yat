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
	Flags SelFlags
	Limit int
	Path  Path
	Group Group
}

// SelFlags is a set of selector flags.
// The [SDATA] and [SREPLY] flags narrow the set of selected messages.
type SelFlags uint32

const (

	// SDATA selects messages with at least 1 byte of data.
	SDATA SelFlags = 1 << iota

	// SREPLY selects messages with a reply path.
	SREPLY

	// SRES is a hint for the server.
	// If it is set, the subscriber intends to respond to every message it receives.
	// The server uses this flag to return more accurate request errors.
	SRES SelFlags = 128
)

type Sub interface {
	Stop()                 // stops the subscription
	Done() <-chan struct{} // closed after the sub stops
}

// Errno identifies a particular Yat error.
type Errno uint32

const (
	ENOENT = Errno(2)  // no responders
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
		return "no responders"

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
