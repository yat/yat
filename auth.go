package yat

import (
	"crypto/x509"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

type RuleSet struct {
	rr []Rule
}

// A Rule containing only Grants applies to all principals.
type Rule struct {
	SPIFFE *SPIFFECond `json:"spiffe"`
	Grants []Grant     `json:"grants"`
}

// SPIFFECond requires a principal to have a matching SPIFFE ID.
type SPIFFECond struct {
	Domain string `json:"domain"`
	Path   Path   `json:"path"`
}

type Grant struct {
	Path    Path     `json:"path"`
	Actions []Action `json:"actions"`
}

// Action is the set of possible client actions.
type Action string

const (
	ActionPub = Action("pub") // publish a message
	ActionSub = Action("sub") // subscribe to a stream of messages
)

type Principal struct {
	Cert *x509.Certificate
}

// SPIFFE ID is spiffe://trust-domain[/path]
var validTrustDomain = regexp.MustCompile("^[-_.a-z0-9]+$")

// NewRuleSet returns a new rule set based on the given rules.
// Changing the rules after calling NewRuleSet is not allowed.
func NewRuleSet(rules []Rule) (*RuleSet, error) {
	for i, r := range rules {
		if r.SPIFFE != nil {
			if r.SPIFFE.Domain == "" {
				return nil, fmt.Errorf("rules[%d].spiffe: empty domain", i)
			}

			if !validTrustDomain.MatchString(r.SPIFFE.Domain) {
				return nil, fmt.Errorf("rules[%d].spiffe: invalid domain", i)
			}
		}

		if len(r.Grants) == 0 {
			return nil, fmt.Errorf("rules[%d]: empty grants", i)
		}

		for j, g := range r.Grants {
			if g.Path.IsZero() {
				return nil, fmt.Errorf("rules[%d].grants[%d]: empty path", i, j)
			}

			if len(g.Actions) == 0 {
				return nil, fmt.Errorf("rules[%d].grants[%d]: empty actions", i, j)
			}

			for _, a := range g.Actions {
				if a != ActionPub && a != ActionSub {
					return nil, fmt.Errorf("rules[%d].grants[%d]: invalid action: %s", i, j, a)
				}
			}
		}
	}

	rs := &RuleSet{
		rr: rules,
	}

	return rs, nil
}

// AllowAll returns a rule set that allows all actions on all paths.
func AllowAll() *RuleSet {
	rs, err := NewRuleSet([]Rule{
		{
			Grants: []Grant{
				{
					Path:    NewPath("**"),
					Actions: []Action{ActionPub, ActionSub},
				},
			},
		},
	})

	if err != nil {
		panic(err)
	}

	return rs
}

// Compile compiles an allow function for the given principal.
// The functions returns true if an action is allowed for a particular path.
func (rs *RuleSet) Compile(p Principal) func(Path, Action) bool {
	var gg []Grant

	for _, r := range rs.rr {
		if r.SPIFFE != nil && !r.SPIFFE.match(p) {
			continue
		}

		for _, g := range r.Grants {
			gg = append(gg, Grant{
				Path:    g.Path.Clone(),
				Actions: slices.Clone(g.Actions),
			})
		}
	}

	return func(p Path, a Action) bool {
		return slices.ContainsFunc(gg, func(g Grant) bool {
			return g.allow(p, a)
		})
	}
}

func (ss SPIFFECond) match(p Principal) bool {
	if p.Cert == nil {
		return false
	}

	if len(p.Cert.URIs) == 0 || len(p.Cert.URIs) > 1 {
		return false
	}

	id := p.Cert.URIs[0]
	if id.Scheme != "spiffe" || len(id.RawQuery) > 0 || id.ForceQuery || id.RawFragment != "" || id.User != nil {
		return false
	}

	var path Path
	var wild bool
	var err error

	if raw := strings.TrimPrefix(id.Path, "/"); raw != "" {
		path, wild, err = ParsePath(raw)
	}

	if wild || err != nil {
		return false
	}

	domain := id.Host
	if !validTrustDomain.MatchString(domain) {
		return false
	}

	if ss.Domain != "" && domain != ss.Domain {
		return false
	}

	if !ss.Path.IsZero() && !ss.Path.Match(path) {
		return false
	}

	return true
}

func (g Grant) allow(p Path, a Action) bool {
	return g.Path.Match(p) && slices.Contains(g.Actions, a)
}
