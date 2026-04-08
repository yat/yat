package yat

import (
	"crypto/x509"
	"errors"
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
	TLS    *TLSCond    `json:"tls"`
	SPIFFE *SPIFFECond `json:"spiffe"`
	Grants []Grant     `json:"grants"`
}

// TLSCond requires a principal to present a certificate with a matching URI SAN.
type TLSCond struct {
	SAN struct {
		URI string `json:"uri"`
	} `json:"san"`
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
		if err := r.validate(); err != nil {
			return nil, fmt.Errorf("rules[%d]: %v", i, err)
		}
	}

	rs := &RuleSet{
		rr: rules,
	}

	return rs, nil
}

// AllowAll returns a rule set that allows all actions on all paths.
func AllowAll() *RuleSet {
	return &RuleSet{
		rr: []Rule{
			{
				Grants: []Grant{
					{
						Path:    NewPath("**"),
						Actions: []Action{ActionPub, ActionSub},
					},
				},
			},
		},
	}
}

// Compile compiles an allow function for the given principal.
// The functions returns true if an action is allowed for a particular path.
func (rs *RuleSet) Compile(p Principal) func(Path, Action) bool {
	var gg []Grant

	for _, r := range rs.rr {
		if !r.match(p) {
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

func (r Rule) match(p Principal) bool {
	return (r.TLS == nil || r.TLS.match(p)) &&
		(r.SPIFFE == nil || r.SPIFFE.match(p))
}

func (r Rule) validate() error {
	if r.SPIFFE != nil {
		if r.SPIFFE.Domain == "" {
			return errors.New("spiffe: empty domain")
		}

		if !validTrustDomain.MatchString(r.SPIFFE.Domain) {
			return errors.New("spiffe: invalid domain")
		}
	}

	if len(r.Grants) == 0 {
		// FIX: is this actually an error?
		return errors.New("empty grants")
	}

	for i, g := range r.Grants {
		if g.Path.IsZero() {
			return fmt.Errorf("grants[%d]: empty path", i)
		}

		if len(g.Actions) == 0 {
			return fmt.Errorf("grants[%d]: empty actions", i)
		}

		for _, a := range g.Actions {
			if a != ActionPub && a != ActionSub {
				return fmt.Errorf("grants[%d]: invalid action: %s", i, a)
			}
		}
	}

	return nil
}

func (tc TLSCond) match(p Principal) bool {
	if p.Cert == nil {
		return false
	}

	if len(p.Cert.URIs) == 0 || len(p.Cert.URIs) > 1 {
		return false
	}

	return smatch(tc.SAN.URI, p.Cert.URIs[0].String())
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

// smatch returns true if the string matches the pattern.
// A * at the end of the pattern matches any suffix.
func smatch(pat string, str string) bool {
	if p, ok := strings.CutSuffix(pat, "*"); ok {
		return strings.HasPrefix(str, p)
	}
	return str == pat
}
