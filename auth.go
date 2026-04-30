package yat

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"yat.io/yat/internal/interpol"
)

type RuleSet struct {
	rr []Rule
	vv map[string]*oidc.IDTokenVerifier
}

// A Rule with no conditions applies to all principals.
type Rule struct {
	TLS    *TLSCond  `json:"tls"`
	JWT    *JWTCond  `json:"jwt"`
	Expr   *ExprCond `json:"expr"`
	Grants []Grant   `json:"grants"`
}

// TLSCond requires a principal to have a matching verified certificate.
type TLSCond struct {
	SAN struct {
		URI string `json:"uri"`
	} `json:"san"`
}

// JWTCond requires a principal to have a matching token.
type JWTCond struct {
	Issuer   string `json:"iss"`
	Audience string `json:"aud"`
	Subject  string `json:"sub"`
}

// ExprCond requires a CEL expression to return true for a principal.
type ExprCond struct {
	Match string
	prog  cel.Program
}

type Grant struct {
	Paths   []string `json:"paths"`
	Actions []Action `json:"actions"`
}

// Action is the set of possible client actions.
type Action string

const (
	ActionPub = Action("pub") // publish a message
	ActionSub = Action("sub") // subscribe to a set of paths
)

type Principal struct {
	Cert   *x509.Certificate
	Claims *Claims

	// env is set by RuleSet.Compile to cache
	// the eval environment for expr conditions
	env map[string]any
}

type Claims struct {
	claims map[string]any
}

type AllowFunc func(Path, Action) bool

var jwtAlgs = []jose.SignatureAlgorithm{
	jose.ES256,
	jose.PS256,
	jose.RS256,
}

var rulesEnv *cel.Env

func init() {
	env, err := cel.NewEnv(
		cel.Variable("claims", cel.MapType(cel.StringType, cel.AnyType)),
		cel.Function("interpol",
			cel.Overload("interpol", []*cel.Type{cel.StringType}, cel.StringType,
				cel.UnaryBinding(func(arg ref.Val) ref.Val {
					s := string(arg.(types.String))
					if strings.Contains(s, "*") {
						return types.NewErr("wildcard interpolation")
					}
					return arg
				}),
			),
		),
	)

	if err != nil {
		panic(err)
	}

	rulesEnv = env
}

// NewRuleSet builds a new rule set from the given rules.
// The context is used for OIDC discovery requests
// if any of the rules have JWT conditions.
func NewRuleSet(ctx context.Context, rules []Rule) (*RuleSet, error) {
	rr := make([]Rule, len(rules))
	for i, r := range rules {
		rr[i] = r.clone()
	}

	vv := map[string]*oidc.IDTokenVerifier{}

	for i, r := range rr {
		if err := r.validate(); err != nil {
			return nil, fmt.Errorf("rules[%d]: %v", i, err)
		}

		if r.JWT != nil && vv[r.JWT.Issuer] == nil {
			p, err := oidc.NewProvider(ctx, r.JWT.Issuer)
			if err != nil {
				return nil, fmt.Errorf("rules[%d].jwt: %v", i, err)
			}

			var algs []string
			for _, a := range jwtAlgs {
				algs = append(algs, string(a))
			}

			vv[r.JWT.Issuer] = p.Verifier(&oidc.Config{
				SupportedSigningAlgs: algs,
				SkipClientIDCheck:    true,
			})
		}

		if r.Expr != nil && r.Expr.prog == nil {
			if err := rr[i].Expr.compile(); err != nil {
				return nil, fmt.Errorf("rules[%d].expr: %v", i, err)
			}
		}
	}

	rs := &RuleSet{
		rr: rr,
		vv: vv,
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
						Paths:   []string{"**"},
						Actions: []Action{ActionPub, ActionSub},
					},
				},
			},
		},
	}
}

// Compile compiles an allow function for the given principal.
// The functions returns true if an act ion is allowed for a particular path.
func (rs *RuleSet) Compile(p Principal) (AllowFunc, error) {
	if len(rs.rr) == 0 {
		return func(Path, Action) bool {
			return false
		}, nil
	}

	p.env = map[string]any{}
	if p.Claims != nil {
		p.env["claims"] = p.Claims.claims
	}

	var allowed []AllowFunc
	for i, r := range rs.rr {
		if !r.match(p) {
			continue
		}

		for j, g := range r.Grants {
			allow, err := g.compile(p)
			if err != nil {
				return nil, fmt.Errorf("rules[%d].grants[%d]: %v", i, j, err)
			}

			allowed = append(allowed, allow)
		}
	}

	return func(p Path, a Action) bool {
		return slices.ContainsFunc(allowed, func(allow AllowFunc) bool {
			return allow(p, a)
		})
	}, nil
}

// VerifyToken parses and verifies a signed JWT.
// The token's issuer must be referenced by at least one rule.
func (rs *RuleSet) VerifyToken(ctx context.Context, raw string) (*Claims, error) {
	tok, err := jwt.ParseSigned(raw, jwtAlgs)
	if err != nil {
		return nil, err
	}

	var unverified struct {
		Issuer string `json:"iss"`
	}

	if err := tok.UnsafeClaimsWithoutVerification(&unverified); err != nil {
		return nil, err
	}

	v, ok := rs.vv[unverified.Issuer]
	if !ok {
		return nil, fmt.Errorf("unknown issuer %s", unverified.Issuer)
	}

	id, err := v.Verify(ctx, string(raw))
	if err != nil {
		return nil, err
	}

	var cc map[string]any
	if err := id.Claims(&cc); err != nil {
		return nil, err
	}

	return &Claims{cc}, nil
}

func (r Rule) match(p Principal) bool {
	return (r.TLS == nil || r.TLS.match(p)) &&
		(r.JWT == nil || r.JWT.match(p)) &&
		(r.Expr == nil || r.Expr.match(p))
}

func (r Rule) validate() error {
	if r.JWT != nil {
		u, err := url.Parse(r.JWT.Issuer)
		if err != nil {
			return fmt.Errorf("jwt: invalid issuer: %v", err)
		}

		if u.Scheme != "https" || !u.IsAbs() {
			return errors.New("jwt: invalid issuer")
		}
	}

	for i, g := range r.Grants {
		if err := g.validate(); err != nil {
			return fmt.Errorf("grants[%d]: %v", i, err)
		}
	}

	return nil
}

func (r Rule) clone() Rule {
	var c Rule
	if r.TLS != nil {
		c.TLS = &TLSCond{
			SAN: r.TLS.SAN,
		}
	}

	if r.JWT != nil {
		c.JWT = &JWTCond{
			Issuer:   r.JWT.Issuer,
			Audience: r.JWT.Audience,
			Subject:  r.JWT.Subject,
		}
	}

	if r.Expr != nil {
		c.Expr = &ExprCond{
			Match: r.Expr.Match,
			prog:  r.Expr.prog,
		}
	}

	c.Grants = make([]Grant, len(r.Grants))
	for i, g := range r.Grants {
		c.Grants[i] = Grant{
			Paths:   slices.Clone(g.Paths),
			Actions: slices.Clone(g.Actions),
		}
	}

	return c
}

func (tc TLSCond) match(p Principal) bool {
	if p.Cert == nil {
		return false
	}

	if len(p.Cert.URIs) == 0 {
		return false
	}

	return slices.ContainsFunc(p.Cert.URIs, func(u *url.URL) bool {
		return smatch(tc.SAN.URI, u.String())
	})
}

func (jc JWTCond) match(p Principal) bool {
	if p.Claims == nil {
		return false
	}

	if iss, _ := p.Claims.claims["iss"].(string); iss != jc.Issuer {
		return false
	}

	if jc.Subject != "" {
		if sub, _ := p.Claims.claims["sub"].(string); !smatch(jc.Subject, sub) {
			return false
		}
	}

	if jc.Audience != "" {
		aud, ok := p.Claims.claims["aud"]
		if !ok {
			return false
		}

		switch aud := aud.(type) {
		case string:
			if aud != jc.Audience {
				return false
			}

		case []any:
			if !slices.ContainsFunc(aud, func(v any) bool {
				s, ok := v.(string)
				return ok && s == jc.Audience
			}) {
				return false
			}

		default:
			return false
		}
	}

	return true
}

func (ec ExprCond) MarshalJSON() ([]byte, error) {
	return json.Marshal(ec.Match)
}

func (ec *ExprCond) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &ec.Match); err != nil {
		return err
	}

	ec.prog = nil
	return nil
}

func (ec *ExprCond) compile() error {
	ast, issues := rulesEnv.Compile(ec.Match)
	if err := issues.Err(); err != nil {
		return err
	}

	if ast.OutputType() != cel.BoolType {
		return errors.New("not a bool")
	}

	p, err := rulesEnv.Program(ast)
	if err != nil {
		panic(err)
	}

	ec.prog = p
	return nil
}

func (ec ExprCond) match(p Principal) bool {
	val, _, _ := ec.prog.Eval(p.env)
	ok, match := val.Value().(bool)
	return ok && match
}

func (g Grant) compile(p Principal) (AllowFunc, error) {
	var paths []Path

	for i, gp := range g.Paths {
		pat, err := compilePath(gp, p)
		if err != nil {
			return nil, fmt.Errorf("paths[%d]: %v", i, err)
		}

		paths = append(paths, pat)
	}

	return func(p Path, a Action) bool {
		return slices.Contains(g.Actions, a) &&
			slices.ContainsFunc(paths, func(pat Path) bool {
				return pat.Match(p)
			})
	}, nil
}

func (g Grant) validate() error {
	for i, p := range g.Paths {
		eg, err := interpol.Replace(rulesEnv, p, "eg")
		if err != nil {
			return fmt.Errorf("paths[%d]: %v", i, err)
		}

		p, err := ParsePath(eg)
		if err != nil {
			return fmt.Errorf("paths[%d]: %v", i, err)
		}

		if p.IsPostbox() {
			return fmt.Errorf("paths[%d]: invalid postbox", i)
		}
	}

	for _, a := range g.Actions {
		if a != ActionPub && a != ActionSub {
			return fmt.Errorf("invalid action: %s", a)
		}
	}

	return nil
}

func compilePath(s string, p Principal) (Path, error) {
	prg, err := interpol.Compile(rulesEnv, s)
	if err != nil {
		return Path{}, err
	}

	if prg != nil {
		v, _, err := prg.Eval(p.env)
		if err != nil {
			return Path{}, err
		}
		s = v.Value().(string)
	}

	path, err := ParsePath(s)
	if err != nil {
		return Path{}, err
	}
	if path.IsPostbox() {
		return Path{}, errors.New("invalid postbox")
	}
	return path, nil
}

// smatch returns true if the string matches the pattern.
// The pattern may include * wildcards to match a run of 0 or more characters.
func smatch(pat string, str string) bool {
	pp := strings.Split(pat, "*")
	if len(pp) == 1 {
		return str == pat
	}

	// beginning
	str, ok := strings.CutPrefix(str, pp[0])
	if !ok {
		return false
	}

	// middle
	for _, p := range pp[1 : len(pp)-1] {
		i := strings.Index(str, p)
		if i == -1 {
			return false
		}

		str = str[i+len(p):]
	}

	// end
	return strings.HasSuffix(str, pp[len(pp)-1])
}
