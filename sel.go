package yat

import (
	"fmt"
	"unique"

	"github.com/yat/yat/topic"
)

type Sel struct {
	Topic topic.Path // * **
	Limit int
	Group DeliveryGroup
	Flags SelFlags
}

type DeliveryGroup struct {
	h unique.Handle[string]
}

func (g DeliveryGroup) String() string {
	return g.h.Value()
}

// SelFlags is a set of flags selecting particular message fields.
// The [DATA] flag selects messages with at least 1 byte of data
// and the [INBOX] flag selects messages with an inbox.
type SelFlags int

const (
	DATA  = SelFlags(1 << iota) // message has data
	INBOX                       // message has an inbox
)

// String returns the name of the flag, like "DATA" or "INBOX".
// Unknown values are styled "SelFlags(n)".
func (sf SelFlags) String() string {
	switch sf {
	case DATA:
		return "DATA"

	case INBOX:
		return "INBOX"

	default:
		return fmt.Sprintf("SelFlags(%d)", sf)
	}
}
