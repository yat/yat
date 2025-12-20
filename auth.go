package yat

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"slices"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/cel-go/cel"
	"sigs.k8s.io/yaml"
)

type Auth struct {
	rr []AuthRule
	tv map[string]*oidc.IDTokenVerifier
}

// AuthRule is a set of allowed actions with particular requirements.
// A rule with no requirements applies to all contexts.
type AuthRule struct {

	// Match, if not nil, is required to return true.
	Match func(AuthContext) bool

	// Token, if not nil, is required to match.
	Token *AuthTokenSpec

	// Grants is the set of actions allowed by the rule.
	Grants []AuthGrant
}

// AuthGrant associates a path with a set of allowed actions.
type AuthGrant struct {
	Path    Path
	Actions []Action
}

// AuthTokenSpec describes a set of auth tokens.
type AuthTokenSpec struct {
	Issuer   string
	Audience string
	Claims   map[string]any
}

// AuthContext holds the information required to compile an authz func
// for a client connection. When a connection is opened or updates
// its identity, the server recompiles the connection's auth func by
// building an auth context and passing it to [Auth.Compile].
type AuthContext struct {
	Address netip.AddrPort
	Token   *AuthToken
}

// AuthToken is a JSON web token parsed and verified by [Auth.Verify].
type AuthToken struct {
	claims map[string]any
}

// Action is the set of possible actions.
// Valid actions are [PubAction] or [SubAction].
type Action string

const (
	PubAction = Action("pub") // publish a message
	SubAction = Action("sub") // subscribe to a stream of messages
)

// validJWSAlgorithms are the alg values supported by [Auth.Verify].
// A particular provider may not support all of these algs.
var validJWSAlgorithms = []jose.SignatureAlgorithm{
	jose.EdDSA,
	jose.ES256,
	jose.PS256,
	jose.RS256,
}

// authEnv is the environment used to evaluate auth expressions. See init().
var authEnv *cel.Env

// NewAuth returns a new auth provider for the given rules.
// The rules must not be modified after NewAuth is called.
func NewAuth(ctx context.Context, rules []AuthRule) (*Auth, error) {
	tv := map[string]*oidc.IDTokenVerifier{}

	for i, r := range rules {
		if r.Token == nil {
			continue
		}

		if r.Token.Issuer == "" {
			return nil, fmt.Errorf("rules[%d]: issuer must be an http or https url", i)
		}

		p, err := oidc.NewProvider(ctx, r.Token.Issuer)
		if err != nil {
			return nil, fmt.Errorf("rules[%d]: %v", i, err)
		}

		ocfg := &oidc.Config{ClientID: r.Token.Audience}
		if ocfg.ClientID == "" {
			ocfg.SkipClientIDCheck = true
		}

		tv[r.Token.Issuer] = p.Verifier(ocfg)
	}

	a := &Auth{
		rr: rules,
		tv: tv,
	}

	return a, nil
}

// ReadAuthRulesFile reads and parses a set of auth rules from the named file,
// which can contain YAML or JSON. See testdata/auth/ in this package for examples.
func ReadAuthRulesFile(name string) (rules []AuthRule, err error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return
	}

	var rulesFile struct {
		Auth struct {
			Rules []struct {
				Match string `json:"match"`

				Token *struct {
					Issuer   string         `json:"issuer"`
					Audience string         `json:"audience"`
					Claims   map[string]any `json:"claims"`
				} `json:"token"`

				Grants []struct {
					Path    Path     `json:"path"`
					Actions []Action `json:"actions"`
				} `json:"grants"`
			} `json:"rules"`
		} `json:"auth"`
	}

	err = yaml.UnmarshalStrict(data, &rulesFile)
	if err != nil {
		return
	}

	for i, fr := range rulesFile.Auth.Rules {
		r := AuthRule{}

		if fr.Match != "" {
			r.Match, err = compileAuthExpr2(fr.Match)
			if err != nil {
				err = fmt.Errorf("rules[%d]: %v", i, err)
				return
			}
		}

		if fr.Token != nil {
			r.Token = &AuthTokenSpec{
				Issuer:   fr.Token.Issuer,
				Audience: fr.Token.Audience,
				Claims:   fr.Token.Claims,
			}
		}

		for _, fg := range fr.Grants {
			r.Grants = append(r.Grants, AuthGrant{
				Path:    fg.Path,
				Actions: fg.Actions,
			})
		}

		rules = append(rules, r)
	}

	return
}

// AllowAll returns an auth provider that allows all actions.
func AllowAll() *Auth {
	return &Auth{
		rr: []AuthRule{
			{
				Grants: []AuthGrant{
					{
						Path: NewPath("**"),
						Actions: []Action{
							PubAction,
							SubAction,
						},
					},
				},
			},
		},
	}
}

// Compile compiles a function that returns true if an action is allowed in the given context.
func (a *Auth) Compile(ac AuthContext) (allow func(Path, Action) bool) {
	if a == nil {
		return func(Path, Action) bool {
			return false
		}
	}

	var grants []AuthGrant
	for _, ar := range a.rr {
		if ar.match(ac) {
			grants = append(grants, ar.Grants...)
		}
	}

	return func(p Path, a Action) bool {
		return slices.ContainsFunc(grants, func(g AuthGrant) bool {
			return g.allow(p, a)
		})
	}
}

// Verify parses and verifies a token according to the rules.
func (a *Auth) Verify(ctx context.Context, rawToken string) (*AuthToken, error) {
	if a == nil {
		return nil, errors.New("auth is disabled")
	}

	ut, err := jwt.ParseSigned(rawToken, validJWSAlgorithms)
	if err != nil {
		return nil, err
	}

	var uc struct {
		Iss string `json:"iss"`
	}

	if err := ut.UnsafeClaimsWithoutVerification(&uc); err != nil {
		return nil, err
	}

	v, ok := a.tv[uc.Iss]
	if !ok {
		return nil, fmt.Errorf("%s: unsupported issuer", uc.Iss)
	}

	id, err := v.Verify(ctx, rawToken)
	if err != nil {
		return nil, err
	}

	var claims map[string]any
	if err := id.Claims(&claims); err != nil {
		return nil, err
	}

	return &AuthToken{claims}, nil
}

// match returns true if the given context satisfies the rule.
func (ar AuthRule) match(ac AuthContext) bool {
	if ar.Match != nil && !ar.Match(ac) {
		return false
	}

	if ar.Token != nil && !ar.Token.match(ac.Token) {
		return false
	}

	return true
}

// match returns true if the given token matches the spec.
func (spec AuthTokenSpec) match(at *AuthToken) bool {
	if at == nil {
		return false
	}

	if iss, ok := at.claims["iss"].(string); !ok || iss != spec.Issuer {
		return false
	}

	if spec.Audience != "" {
		raw, ok := at.claims["aud"]
		if !ok {
			return false
		}

		var got jwt.Audience
		switch v := raw.(type) {
		case string:
			got = append(got, v)

		case []string:
			got = append(got, v...)
		}

		if !got.Contains(spec.Audience) {
			return false
		}
	}

	if spec.Claims != nil {
		for name, want := range spec.Claims {
			if got, ok := at.claims[name]; !ok || !reflect.DeepEqual(want, got) {
				return false
			}
		}
	}

	return true
}

// allow returns true if the grant allows the given action.
func (g AuthGrant) allow(p Path, a Action) bool {
	return g.Path.Match(p) && slices.Contains(g.Actions, a)
}

func compileAuthExpr2(expr string) (func(ac AuthContext) bool, error) {
	ast, issues := authEnv.Parse(expr)
	if err := issues.Err(); err != nil {
		return nil, err
	}

	checked, issues := authEnv.Check(ast)
	if err := issues.Err(); err != nil {
		return nil, err
	}

	out := checked.OutputType()
	if !reflect.DeepEqual(out, cel.BoolType) && !reflect.DeepEqual(out, cel.DynType) {
		return nil, fmt.Errorf("match expression type %v != %v", out, cel.BoolType)
	}

	prg, err := authEnv.Program(checked)
	if err != nil {
		return nil, err
	}

	return func(ac AuthContext) bool {
		conn := map[string]any{
			"address": ac.Address.String(),
			"local":   ac.Address.Addr().IsLoopback(),
		}

		if ac.Token != nil {
			conn["token"] = map[string]any{
				"claims": ac.Token.claims,
			}
		}

		v, _, err := prg.Eval(map[string]any{
			"conn": conn,
		})

		if err != nil {
			panic(err)
		}

		ok, _ := v.Value().(bool)
		return ok
	}, nil
}

func init() {
	env, err := cel.NewEnv(
		cel.Variable("conn", cel.MapType(cel.StringType, cel.DynType)),
	)

	if err != nil {
		panic(err)
	}

	authEnv = env
}
