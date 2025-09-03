package yat

import (
	"encoding/json"
	"fmt"
	"strings"

	"yat.io/yat/topic"
)

// Identity holds information identifying a client.
type Identity struct {
	Claims map[string]any
}

type RuleSet struct {
	Rules []Rule `json:"rules"`
}

type Rule struct {
	Name   string            `json:"name,omitempty"`
	Claims map[string]string `json:"token,omitzero"`
	Grants []Grant           `json:"grants,omitempty"`
}

type Grant struct {
	Topic  topic.Path `json:"topic"`
	Action Action     `json:"action"`
}

type Action uint

const (
	PUB = Action(1 << iota) // publish messages
	SUB                     // receive messages
)

// Compile compiles a match function for the given identity.
func (rs RuleSet) Compile(id Identity) func(topic.Path, Action) bool {
	var grants []Grant

	// FIX: This limited claims check (got != want) will probably not
	// work, since there's no way to test membership in an array (like aud).

compiling:
	for _, r := range rs.Rules {
		if len(r.Claims) == 0 {
			continue
		}

		for name, want := range r.Claims {
			got, ok := id.Claims[name]
			if !ok || got != want {
				continue compiling
			}
		}

		grants = append(grants, r.Grants...)
	}

	return func(p topic.Path, a Action) bool {
		var aa Action
		for _, g := range grants {
			if g.Topic.Match(p) {
				aa |= g.Action
			}
		}

		return aa&a == a
	}
}

// MarshalJSON marshals a as a JSON array: [], ["pub"], ["sub"], or ["pub", "sub"].
// If a has any bits set other than PUB and SUB, they are lost.
func (a Action) MarshalJSON() ([]byte, error) {
	var names []string

	if a&PUB != 0 {
		names = append(names, "pub")
	}

	if a&SUB != 0 {
		names = append(names, "sub")
	}

	return json.Marshal(names)
}

// UnmarshalJSON unmarshals a from a JSON array of action names.
// Case doesnt matter, but an error is returned if a name is unknown.
func (a *Action) UnmarshalJSON(b []byte) error {
	var names []string
	if err := json.Unmarshal(b, &names); err != nil {
		return err
	}

	*a = 0
	for _, name := range names {
		switch strings.ToLower(name) {
		case "pub":
			*a |= PUB

		case "sub":
			*a |= SUB

		default:
			return fmt.Errorf("unknown Action %s", name)
		}
	}

	return nil
}

// String returns the action set as a string, like "PUB", "SUB", or "PUB|SUB".
func (a Action) String() string {
	var parts []string

	if a&PUB != 0 {
		parts = append(parts, "PUB")
	}

	if a&SUB != 0 {
		parts = append(parts, "SUB")
	}

	if rest := a &^ (PUB | SUB); rest != 0 {
		parts = append(parts, fmt.Sprintf("%#x", uint(rest)))
	}

	return strings.Join(parts, "|")
}
