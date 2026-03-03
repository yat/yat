package yat

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
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

// TokenSpec specifies a JWT matcher.
// The zero spec never matches.
type TokenSpec struct {
	Issuer   string
	Audience string
	Subject  string

	// anyToken is true for tokens returned by [AnyToken].
	// It causes [Rule.match] to ignore the spec fields
	// and match any valid token.
	anyToken bool
}

type Grant struct {
	Path    Path
	Actions []Action
}

// Action is the set of possible client actions.
type Action string

const (
	ActionPub = Action("pub") // publish a message
	ActionSub = Action("sub") // subscribe to a stream of messages
)

// Token is a JWT parsed and verified by [RuleSet.Verify].
type Token struct {
	claims map[string]any
	public jwt.Claims
	valid  bool
}

type Identity struct {
	Conn  net.Conn // not yet supported by auth rules
	Token *Token
}

// ValidJOSEAlgs are the alg values supported by [Auth.Verify].
// A particular provider may not support all of these algs.
var ValidJOSEAlgs = []jose.SignatureAlgorithm{
	jose.EdDSA,
	jose.ES256,
	jose.PS256,
	jose.RS256,
}

var errUnknownIssuer = errors.New("unknown issuer")

func NewRuleSet(ctx context.Context, rules []Rule) (*RuleSet, error) {
	vv := map[string]*oidc.IDTokenVerifier{}
	for i, r := range rules {
		if r.Token != nil {
			if r.Token.Issuer == "" {
				return nil, fmt.Errorf("rules[%d].token: missing issuer", i)
			}

			ctx := ctx
			iss := r.Token.Issuer

			// special treatment:
			// - the iss claim may differ
			// - use cluster ca cert for discovery
			// - use pod token for discovery
			if iss == "https://kubernetes.default.svc" {
				tokenBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
				if err != nil {
					return nil, err
				}

				unparsedToken := string(tokenBytes)
				parsed, err := jwt.ParseSigned(string(unparsedToken), ValidJOSEAlgs)
				if err != nil {
					return nil, err
				}

				var claims jwt.Claims
				if err := parsed.UnsafeClaimsWithoutVerification(&claims); err != nil {
					return nil, err
				}

				rawRoots, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
				if err != nil {
					return nil, err
				}

				roots := x509.NewCertPool()
				if !roots.AppendCertsFromPEM(rawRoots) {
					return nil, errors.New("no roots")
				}

				iss = claims.Issuer
				r.Token.Issuer = iss
				ctx = oidc.InsecureIssuerURLContext(ctx, iss)
				ctx = oidc.ClientContext(ctx, &http.Client{
					Transport: authTransport{
						Token: unparsedToken,
						RoundTripper: &http.Transport{
							TLSClientConfig: &tls.Config{
								RootCAs: roots,
							},
						},
					},
				})
			}

			op, err := oidc.NewProvider(ctx, r.Token.Issuer)
			if err != nil {
				return nil, err
			}

			vv[iss] = op.Verifier(&oidc.Config{
				SkipClientIDCheck: true,
			})
		}
	}

	return &RuleSet{rules, vv}, nil
}

// AllowAll returns a rule set that allows all actions on all paths.
func AllowAll() *RuleSet {
	rs, err := NewRuleSet(context.Background(), []Rule{
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

func (rs *RuleSet) Verify(ctx context.Context, jwtBytes []byte) (*Token, error) {
	unparsed := string(jwtBytes)
	parsed, err := jwt.ParseSigned(unparsed, ValidJOSEAlgs)
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

	verified, err := v.Verify(ctx, unparsed)
	if err != nil {
		return nil, err
	}

	var token Token
	for _, v := range []any{&token.public, &token.claims} {
		if err := verified.Claims(v); err != nil {
			return nil, err
		}
	}

	token.valid = true
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

// AnyToken returns an auth token spec matching any verified token.
func AnyToken() *TokenSpec {
	return &TokenSpec{anyToken: true}
}

func (r Rule) match(id Identity) bool {
	if spec := r.Token; spec != nil {
		if id.Token == nil {
			return false
		}

		return spec.match(*id.Token)
	}

	return true
}

func (ts TokenSpec) match(t Token) bool {
	if (ts == TokenSpec{}) || !t.valid {
		return false
	}

	if ts.anyToken {
		return true
	}

	switch {
	case ts.Issuer != "" && t.public.Issuer != ts.Issuer:
		return false

	case ts.Audience != "" && !t.public.Audience.Contains(ts.Audience):
		return false

	case ts.Subject != "" && t.public.Subject != ts.Subject:
		return false

	default:
		return true
	}
}

func (g Grant) allow(p Path, a Action) bool {
	return g.Path.Match(p) && slices.Contains(g.Actions, a)
}

type authTransport struct {
	Token string
	http.RoundTripper
}

func (at authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.Header.Set("authorization", "Bearer "+at.Token)
	return at.RoundTripper.RoundTrip(r)
}
