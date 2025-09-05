package yat

import (
	"fmt"
	"unique"

	"yat.io/yat/topic"
)

type Sel struct {
	Topic topic.Path    `json:"topic,omitzero"`
	Limit int           `json:"limit,omitzero"`
	Group DeliveryGroup `json:"group,omitzero"`
	Flags SelFlags      `json:"flags,omitzero"`
}

type DeliveryGroup struct {
	h unique.Handle[string]
}

// Group returns the delivery group representing the given value.
func Group[T ~[]byte | ~string](value T) DeliveryGroup {
	return DeliveryGroup{unique.Make(string(value))}
}

// IsZero returns true if the g is the zero group.
func (g DeliveryGroup) IsZero() bool {
	return g == DeliveryGroup{}
}

// Equal returns true if the groups are equal.
// It is exactly the same operation as g == other.
func (g DeliveryGroup) Equal(other DeliveryGroup) bool {
	return g == other
}

// String returns the name of the group.
func (g DeliveryGroup) String() string {
	if g.IsZero() {
		return ""
	}
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
