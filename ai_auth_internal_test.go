package yat

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func TestTokenSpec_match(t *testing.T) {
	matched := Token{
		public: jwt.Claims{
			Issuer:   "https://issuer.example",
			Audience: jwt.Audience{"client-1", "client-2"},
			Subject:  "user-123",
		},
		valid: true,
	}

	tcs := []struct {
		name string
		spec TokenSpec
		tok  Token
		want bool
	}{
		{
			name: "empty spec never matches",
			spec: TokenSpec{},
			tok:  matched,
			want: false,
		},
		{
			name: "issuer mismatch",
			spec: TokenSpec{Issuer: "https://other.example"},
			tok:  matched,
			want: false,
		},
		{
			name: "audience mismatch",
			spec: TokenSpec{Audience: "other-client"},
			tok:  matched,
			want: false,
		},
		{
			name: "subject mismatch",
			spec: TokenSpec{Subject: "other-user"},
			tok:  matched,
			want: false,
		},
		{
			name: "all fields match",
			spec: TokenSpec{
				Issuer:   "https://issuer.example",
				Audience: "client-2",
				Subject:  "user-123",
			},
			tok:  matched,
			want: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.spec.match(tc.tok); got != tc.want {
				t.Fatalf("match: %t != %t", got, tc.want)
			}
		})
	}
}

func TestRule_match(t *testing.T) {
	authed := Identity{Token: &Token{valid: true}}

	t.Run("nil token spec matches anonymous identity", func(t *testing.T) {
		if !(Rule{}).match(Identity{}) {
			t.Fatal("no match")
		}
	})

	t.Run("empty token spec never matches", func(t *testing.T) {
		rule := Rule{Token: &TokenSpec{}}

		if rule.match(Identity{}) {
			t.Fatal("unexpected match")
		}
		if rule.match(authed) {
			t.Fatal("unexpected match")
		}
	})

	t.Run("AnyToken matches authenticated identity", func(t *testing.T) {
		rule := Rule{Token: AnyToken()}

		if rule.match(Identity{}) {
			t.Fatal("unexpected match")
		}
		if !rule.match(authed) {
			t.Fatal("no match")
		}
	})

	t.Run("AnyToken rejects invalid token", func(t *testing.T) {
		rule := Rule{Token: AnyToken()}

		if rule.match(Identity{Token: &Token{}}) {
			t.Fatal("unexpected match")
		}
	})

	t.Run("claim match rejects invalid token", func(t *testing.T) {
		rule := Rule{
			Token: &TokenSpec{Subject: "user-123"},
		}
		id := Identity{
			Token: &Token{
				public: jwt.Claims{Subject: "user-123"},
			},
		}

		if rule.match(id) {
			t.Fatal("unexpected match")
		}
	})

	t.Run("matching token spec delegates to token claims", func(t *testing.T) {
		rule := Rule{
			Token: &TokenSpec{Subject: "user-123"},
		}
		id := Identity{
			Token: &Token{
				public: jwt.Claims{Subject: "user-123"},
				valid:  true,
			},
		}

		if !rule.match(id) {
			t.Fatal("no match")
		}
	})
}

func TestGrant_allow(t *testing.T) {
	grant := Grant{
		Path:    NewPath("chat/**"),
		Actions: []Action{ActionPub},
	}

	if !grant.allow(NewPath("chat/room"), ActionPub) {
		t.Fatal("no match")
	}
	if grant.allow(NewPath("chat/room"), ActionSub) {
		t.Fatal("unexpected action match")
	}
	if grant.allow(NewPath("other/room"), ActionPub) {
		t.Fatal("unexpected path match")
	}
	if (Grant{}).allow(NewPath("chat/room"), ActionPub) {
		t.Fatal("zero grant matched")
	}
}

func TestRuleSetVerify_internalClaims(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	issuer := "https://issuer.example"
	clientID := "client-123"
	subject := "user-123"

	key := newAuthTestKey(t, jose.RS256)
	raw := signAuthTestToken(t, jose.RS256, key.private, jwt.Claims{
		Issuer:   issuer,
		Subject:  subject,
		Audience: jwt.Audience{clientID},
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(now.Add(time.Hour)),
	}, map[string]any{
		"role": "admin",
		"scp":  []string{"pub", "sub"},
	})

	rs, err := NewRuleSet(nil, map[string]*oidc.IDTokenVerifier{
		issuer: newAuthTestVerifier(issuer, clientID, jose.RS256, key.public, now),
	})
	if err != nil {
		t.Fatal(err)
	}

	tok, err := rs.Verify(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}

	if tok.public.Issuer != issuer {
		t.Fatalf("issuer: %q != %q", tok.public.Issuer, issuer)
	}
	if tok.public.Subject != subject {
		t.Fatalf("subject: %q != %q", tok.public.Subject, subject)
	}
	if !tok.public.Audience.Contains(clientID) {
		t.Fatalf("audience missing %q", clientID)
	}
	if got := tok.claims["role"]; got != "admin" {
		t.Fatalf("role: %v != %q", got, "admin")
	}

	scopes, ok := tok.claims["scp"].([]any)
	if !ok {
		t.Fatalf("scp type: %T", tok.claims["scp"])
	}
	if len(scopes) != 2 || scopes[0] != "pub" || scopes[1] != "sub" {
		t.Fatalf("scp: %v", scopes)
	}
}

func TestRuleSetVerify_unknownIssuer(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()

	key := newAuthTestKey(t, jose.RS256)
	raw := signAuthTestToken(t, jose.RS256, key.private, jwt.Claims{
		Issuer:   "https://unknown.example",
		Subject:  "user-123",
		Audience: jwt.Audience{"client-123"},
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(now.Add(time.Hour)),
	}, nil)

	rs, err := NewRuleSet(nil, map[string]*oidc.IDTokenVerifier{
		"https://issuer.example": newAuthTestVerifier(
			"https://issuer.example",
			"client-123",
			jose.RS256,
			key.public,
			now,
		),
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = rs.Verify(context.Background(), raw)
	if !errors.Is(err, errUnknownIssuer) {
		t.Fatalf("error: %v", err)
	}
}

type authTestKey struct {
	private any
	public  crypto.PublicKey
}

func newAuthTestKey(t *testing.T, alg jose.SignatureAlgorithm) authTestKey {
	t.Helper()

	switch alg {
	case jose.RS256, jose.PS256:
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		return authTestKey{private: key, public: &key.PublicKey}

	case jose.ES256:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return authTestKey{private: key, public: &key.PublicKey}

	case jose.EdDSA:
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return authTestKey{private: private, public: public}

	default:
		t.Fatalf("unsupported algorithm %q", alg)
		return authTestKey{}
	}
}

func newAuthTestVerifier(
	issuer string,
	clientID string,
	alg jose.SignatureAlgorithm,
	public crypto.PublicKey,
	now time.Time,
) *oidc.IDTokenVerifier {
	return oidc.NewVerifier(issuer, &oidc.StaticKeySet{
		PublicKeys: []crypto.PublicKey{public},
	}, &oidc.Config{
		ClientID:             clientID,
		SupportedSigningAlgs: []string{string(alg)},
		Now: func() time.Time {
			return now
		},
	})
}

func signAuthTestToken(
	t *testing.T,
	alg jose.SignatureAlgorithm,
	key any,
	claims jwt.Claims,
	privateClaims map[string]any,
) []byte {
	t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: alg,
		Key:       key,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	builder := jwt.Signed(signer).Claims(claims)
	if privateClaims != nil {
		builder = builder.Claims(privateClaims)
	}

	raw, err := builder.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return []byte(raw)
}
