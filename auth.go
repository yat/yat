package yat

import (
	"context"
	"errors"
	"slices"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type RuleSet struct {
	rr []Rule
	vv map[string]*oidc.IDTokenVerifier
}

type Rule struct {
	Token  *TokenSpec
	Grants []Grant
}

type TokenSpec struct {
	Issuer   string
	Audience string
	Subject  string
}

type Grant struct {
	Path    Path
	Actions []Action
}

// Action is the set of possible actions.
// Valid actions are [PubAction] or [SubAction].
type Action string

const (
	PubAction = Action("pub") // publish a message
	SubAction = Action("sub") // subscribe to a stream of messages
)

// Token is a JWT returned by [RuleSet.Verify].
type Token struct {
	pub jwt.Claims
	all map[string]any
}

type Identity struct {
	Token *Token
}

// validAlgs are the alg values supported by [Auth.Verify].
// A particular provider may not support all of these algs.
var validAlgs = []jose.SignatureAlgorithm{
	jose.EdDSA,
	jose.ES256,
	jose.PS256,
	jose.RS256,
}

var errUnknownIssuer = errors.New("unknown issuer")

func NewRuleSet(rules []Rule, verifiers map[string]*oidc.IDTokenVerifier) (*RuleSet, error) {
	return &RuleSet{rules, verifiers}, nil
}

func (rs *RuleSet) Verify(ctx context.Context, rawToken string) (*Token, error) {
	parsed, err := jwt.ParseSigned(rawToken, validAlgs)
	if err != nil {
		return nil, err
	}

	var unverified struct {
		Iss string `json:"iss"`
	}

	if err := parsed.UnsafeClaimsWithoutVerification(&unverified); err != nil {
		return nil, err
	}

	v, known := rs.vv[unverified.Iss]
	if !known {
		return nil, errUnknownIssuer
	}

	verified, err := v.Verify(ctx, rawToken)
	if err != nil {
		return nil, err
	}

	var token Token
	for _, v := range []any{&token.pub, &token.all} {
		if err := verified.Claims(v); err != nil {
			return nil, err
		}
	}

	return &token, nil
}

func (rs *RuleSet) Compile(id Identity) func(Path, Action) bool {
	var grants []Grant
	for _, r := range rs.rr {
		if r.match(id) {
			grants = append(grants, r.Grants...)
		}
	}

	return func(p Path, a Action) bool {
		return slices.ContainsFunc(grants, func(g Grant) bool {
			return g.allow(p, a)
		})
	}
}

func (r Rule) match(id Identity) bool {
	if spec := r.Token; spec != nil {
		if !spec.match(id.Token) {
			return false
		}
	}

	return true
}

func (ts TokenSpec) match(t *Token) bool {
	if t == nil {
		return false
	}

	switch {
	case ts.Issuer != "" && t.pub.Issuer != ts.Issuer:
		return false

	case ts.Audience != "" && !t.pub.Audience.Contains(ts.Audience):
		return false

	case ts.Subject != "" && t.pub.Subject != ts.Subject:
		return false

	default:
		return true
	}
}

func (g Grant) allow(p Path, a Action) bool {
	return g.Path.Match(p) && slices.Contains(g.Actions, a)
}
