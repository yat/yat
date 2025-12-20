package yat

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/netip"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func TestAuthCompileNil(t *testing.T) {
	var a *Auth

	allow := a.Compile(AuthContext{})
	if allow(NewPath("any"), PubAction) {
		t.Fatal("nil auth allowed publish")
	}

	if allow(NewPath("any"), SubAction) {
		t.Fatal("nil auth allowed subscribe")
	}
}

func TestAuthAllowAll(t *testing.T) {
	allow := AllowAll().Compile(AuthContext{})

	if !allow(NewPath("x"), PubAction) {
		t.Fatal("publish not allowed")
	}

	if !allow(NewPath("x/y/z"), SubAction) {
		t.Fatal("subscribe not allowed")
	}
}

func TestAuthRuleMatching(t *testing.T) {
	token := &AuthToken{
		claims: map[string]any{
			"iss":  "https://issuer.test",
			"aud":  "client",
			"role": "admin",
		},
	}

	rules := []AuthRule{
		{
			Match: func(ac AuthContext) bool {
				return ac.Address.Addr().IsPrivate()
			},
			Token: &AuthTokenSpec{
				Issuer:   "https://issuer.test",
				Audience: "client",
				Claims: map[string]any{
					"role": "admin",
				},
			},
			Grants: []AuthGrant{
				{Path: NewPath("private/**"), Actions: []Action{PubAction}},
			},
		},
		{
			Match: func(AuthContext) bool { return true },
			Grants: []AuthGrant{
				{Path: NewPath("public"), Actions: []Action{SubAction}},
			},
		},
	}

	a := &Auth{rr: rules}

	allow := a.Compile(AuthContext{
		Address: netip.MustParseAddrPort("10.0.0.1:1000"),
		Token:   token,
	})

	if !allow(NewPath("private/topic"), PubAction) {
		t.Fatal("private publish denied")
	}

	if allow(NewPath("private/topic"), SubAction) {
		t.Fatal("private subscribe allowed without grant")
	}

	if !allow(NewPath("public"), SubAction) {
		t.Fatal("public subscribe denied")
	}

	if allow(NewPath("public"), PubAction) {
		t.Fatal("public publish allowed without grant")
	}

	allow = a.Compile(AuthContext{
		Address: netip.MustParseAddrPort("198.51.100.10:9000"),
		Token:   token,
	})

	if allow(NewPath("private/topic"), PubAction) {
		t.Fatal("private publish allowed for non-matching addr")
	}
}

func TestAuthTokenSpecMatch(t *testing.T) {
	rule := AuthRule{
		Token: &AuthTokenSpec{
			Issuer:   "https://issuer.test",
			Audience: "client",
			Claims: map[string]any{
				"group": "dev",
			},
		},
		Grants: []AuthGrant{
			{Path: NewPath("secure"), Actions: []Action{PubAction, SubAction}},
		},
	}

	a := &Auth{rr: []AuthRule{rule}}

	token := &AuthToken{
		claims: map[string]any{
			"iss":   "https://issuer.test",
			"aud":   "client",
			"group": "dev",
		},
	}

	allow := a.Compile(AuthContext{Token: token})
	if !allow(NewPath("secure"), PubAction) {
		t.Fatal("token match denied publish")
	}

	if !allow(NewPath("secure"), SubAction) {
		t.Fatal("token match denied subscribe")
	}

	allow = a.Compile(AuthContext{})
	if allow(NewPath("secure"), PubAction) {
		t.Fatal("allowed publish without token")
	}

	badToken := &AuthToken{
		claims: map[string]any{
			"iss":   "https://issuer.test",
			"aud":   "client",
			"group": "ops",
		},
	}

	allow = a.Compile(AuthContext{Token: badToken})
	if allow(NewPath("secure"), PubAction) {
		t.Fatal("allowed publish with mismatched claim")
	}
}

func TestAuthMultipleRulesAccumulate(t *testing.T) {
	rules := []AuthRule{
		{
			Match: func(AuthContext) bool { return true },
			Grants: []AuthGrant{
				{Path: NewPath("a"), Actions: []Action{PubAction}},
			},
		},
		{
			Match: func(AuthContext) bool { return true },
			Grants: []AuthGrant{
				{Path: NewPath("b/**"), Actions: []Action{SubAction}},
			},
		},
	}

	allow := (&Auth{rr: rules}).Compile(AuthContext{})

	if !allow(NewPath("a"), PubAction) {
		t.Fatal("rule a publish denied")
	}

	if !allow(NewPath("b/c"), SubAction) {
		t.Fatal("rule b subscribe denied")
	}

	if allow(NewPath("b/c"), PubAction) {
		t.Fatal("publish allowed without grant")
	}
}

func TestAuthExprMatch(t *testing.T) {
	match, err := compileAuthExpr2(`conn.local && conn.token.claims["role"] == "loop"`)
	if err != nil {
		t.Fatal(err)
	}

	rule := AuthRule{
		Match: match,
		Grants: []AuthGrant{
			{Path: NewPath("loop/**"), Actions: []Action{SubAction}},
		},
	}

	token := &AuthToken{claims: map[string]any{"role": "loop"}}

	local := (&Auth{rr: []AuthRule{rule}}).Compile(AuthContext{
		Address: netip.MustParseAddrPort("127.0.0.1:1"),
		Token:   token,
	})

	if !local(NewPath("loop/x"), SubAction) {
		t.Fatal("local match denied")
	}

	remote := (&Auth{rr: []AuthRule{rule}}).Compile(AuthContext{
		Address: netip.MustParseAddrPort("198.51.100.1:1"),
		Token:   token,
	})

	if remote(NewPath("loop/x"), SubAction) {
		t.Fatal("remote match allowed")
	}
}

func TestAuthVerify(t *testing.T) {
	issuer := "https://issuer.test"
	audience := "client"

	raw, jwk := mustSignToken(t, issuer, audience, map[string]any{
		"role": "admin",
	})

	ks := staticKeySet{key: jwk}
	verifier := oidc.NewVerifier(issuer, ks, &oidc.Config{ClientID: audience})

	auth := &Auth{
		tv: map[string]*oidc.IDTokenVerifier{
			issuer: verifier,
		},
		rr: []AuthRule{
			{
				Token: &AuthTokenSpec{
					Issuer:   issuer,
					Audience: audience,
					Claims: map[string]any{
						"role": "admin",
					},
				},
				Grants: []AuthGrant{
					{Path: NewPath("secure"), Actions: []Action{PubAction}},
				},
			},
		},
	}

	ctx := context.Background()
	token, err := auth.Verify(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}

	if token.claims["role"] != "admin" {
		t.Fatalf("claims role: %v", token.claims["role"])
	}

	allow := auth.Compile(AuthContext{Token: token})
	if !allow(NewPath("secure"), PubAction) {
		t.Fatal("verified token denied")
	}
}

func TestReadAuthRulesFile_LocalExample(t *testing.T) {
	rules, err := ReadAuthRulesFile("testdata/auth/local.yaml")
	if err != nil {
		t.Fatal(err)
	}

	if want, got := 1, len(rules); got != want {
		t.Fatalf("rules length: %d != %d", got, want)
	}

	allow := (&Auth{rr: rules}).Compile(AuthContext{
		Address: netip.MustParseAddrPort("127.0.0.1:1"),
	})

	if !allow(NewPath("any/path"), PubAction) {
		t.Fatal("local publish denied from file rules")
	}

	if !allow(NewPath("any/path"), SubAction) {
		t.Fatal("local subscribe denied from file rules")
	}

	remote := (&Auth{rr: rules}).Compile(AuthContext{
		Address: netip.MustParseAddrPort("198.51.100.1:1"),
	})

	if remote(NewPath("any/path"), PubAction) {
		t.Fatal("remote publish allowed from file rules")
	}
}

func TestReadAuthRulesFile_WithToken(t *testing.T) {
	rules, err := ReadAuthRulesFile("testdata/auth/token.yaml")
	if err != nil {
		t.Fatal(err)
	}

	if want, got := 1, len(rules); got != want {
		t.Fatalf("rules length: %d != %d", got, want)
	}

	r := rules[0]
	if r.Token == nil {
		t.Fatal("missing token spec")
	}

	if r.Token.Issuer != "https://issuer.test" || r.Token.Audience != "client" {
		t.Fatalf("token spec: %+v", r.Token)
	}

	if got := r.Token.Claims["role"]; got != "admin" {
		t.Fatalf("token claims role: %v", got)
	}

	token := &AuthToken{
		claims: map[string]any{
			"iss":   "https://issuer.test",
			"aud":   "client",
			"role":  "admin",
			"extra": "ok",
		},
	}

	allow := (&Auth{rr: rules}).Compile(AuthContext{Token: token})

	if !allow(NewPath("secure/topic"), PubAction) {
		t.Fatal("token rule publish denied")
	}

	if allow(NewPath("secure/topic"), SubAction) {
		t.Fatal("token rule subscribe allowed without grant")
	}

	bad := &AuthToken{claims: map[string]any{"iss": "https://issuer.test", "aud": "client", "role": "dev"}}

	if (&Auth{rr: rules}).Compile(AuthContext{Token: bad})(NewPath("secure/topic"), PubAction) {
		t.Fatal("bad token allowed publish")
	}

	allow = (&Auth{rr: rules}).Compile(AuthContext{})
	if allow(NewPath("secure/topic"), PubAction) {
		t.Fatal("publish allowed without token")
	}
}

type staticKeySet struct {
	key jose.JSONWebKey
}

func (ks staticKeySet) VerifySignature(_ context.Context, raw string) ([]byte, error) {
	jws, err := jose.ParseSigned(raw, validJWSAlgorithms)
	if err != nil {
		return nil, err
	}

	return jws.Verify(ks.key.Key)
}

func mustSignToken(t *testing.T, iss, aud string, claims map[string]any) (raw string, jwk jose.JSONWebKey) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: priv}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}

	std := map[string]any{
		"iss": iss,
		"sub": "subject",
		"aud": aud,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Add(-time.Minute).Unix(),
	}

	for k, v := range claims {
		std[k] = v
	}

	raw, err = jwt.Signed(signer).Claims(std).Serialize()
	if err != nil {
		t.Fatal(err)
	}

	jwk = jose.JSONWebKey{Key: &priv.PublicKey, Algorithm: string(jose.RS256)}

	return raw, jwk
}
