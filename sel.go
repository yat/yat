package yat

import (
	"unique"

	"yat.io/yat/topic"
)

type Sel struct {
	Topic topic.Path    `json:"topic,omitzero"`
	Limit int           `json:"limit,omitzero"`
	Group DeliveryGroup `json:"group,omitzero"`
}

type DeliveryGroup struct {
	h unique.Handle[string]
}

// Group returns the delivery group representing the given value.
// The zero group is returned if len(value) is 0.
func Group[T ~[]byte | ~string](value T) DeliveryGroup {
	if len(value) == 0 {
		return DeliveryGroup{}
	}
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
