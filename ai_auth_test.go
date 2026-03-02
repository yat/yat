package yat_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"yat.io/yat"
)

func TestRuleSetVerifySupportedAlgorithms(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()

	algs := []jose.SignatureAlgorithm{
		jose.RS256,
		jose.PS256,
		jose.ES256,
		jose.EdDSA,
	}

	for _, alg := range algs {
		t.Run(string(alg), func(t *testing.T) {
			issuer := "https://issuer.example/" + string(alg)
			clientID := "client-" + string(alg)
			subject := "user-" + string(alg)

			key := newExternalAuthTestKey(t, alg)
			rs, err := yat.NewRuleSet([]yat.Rule{
				{
					Token: &yat.TokenSpec{
						Issuer:   issuer,
						Audience: clientID,
						Subject:  subject,
					},
					Grants: []yat.Grant{{
						Path:    yat.NewPath("topic/" + string(alg)),
						Actions: []yat.Action{yat.PubAction, yat.SubAction},
					}},
				},
				{
					Token: &yat.TokenSpec{Issuer: issuer},
					Grants: []yat.Grant{{
						Path:    yat.NewPath("feeds/**"),
						Actions: []yat.Action{yat.SubAction},
					}},
				},
			}, map[string]*oidc.IDTokenVerifier{
				issuer: newExternalAuthTestVerifier(issuer, clientID, alg, key.public, now),
			})
			if err != nil {
				t.Fatal(err)
			}

			raw := signExternalAuthTestToken(t, alg, key.private, jwt.Claims{
				Issuer:   issuer,
				Subject:  subject,
				Audience: jwt.Audience{clientID},
				IssuedAt: jwt.NewNumericDate(now),
				Expiry:   jwt.NewNumericDate(now.Add(time.Hour)),
			}, nil)

			tok, err := rs.Verify(context.Background(), raw)
			if err != nil {
				t.Fatal(err)
			}

			allow := rs.Compile(yat.Identity{Token: tok})
			if !allow(yat.NewPath("topic/"+string(alg)), yat.PubAction) {
				t.Fatal("pub not allowed")
			}
			if !allow(yat.NewPath("topic/"+string(alg)), yat.SubAction) {
				t.Fatal("sub not allowed")
			}
			if !allow(yat.NewPath("feeds/private"), yat.SubAction) {
				t.Fatal("feed sub not allowed")
			}
			if allow(yat.NewPath("feeds/private"), yat.PubAction) {
				t.Fatal("unexpected pub grant")
			}
		})
	}
}

func TestRuleSetCompileAnonymousAndAuthenticated(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	issuer := "https://issuer.example"
	clientID := "client-123"
	subject := "user-123"

	key := newExternalAuthTestKey(t, jose.RS256)
	rs, err := yat.NewRuleSet([]yat.Rule{
		{
			Grants: []yat.Grant{{
				Path:    yat.NewPath("public/**"),
				Actions: []yat.Action{yat.SubAction},
			}},
		},
		{
			Token: &yat.TokenSpec{},
			Grants: []yat.Grant{{
				Path:    yat.NewPath("private/**"),
				Actions: []yat.Action{yat.SubAction},
			}},
		},
		{
			Token: &yat.TokenSpec{Subject: subject},
			Grants: []yat.Grant{{
				Path:    yat.NewPath("subject/**"),
				Actions: []yat.Action{yat.PubAction},
			}},
		},
		{
			Token: &yat.TokenSpec{Audience: "other-client"},
			Grants: []yat.Grant{{
				Path:    yat.NewPath("other/**"),
				Actions: []yat.Action{yat.PubAction},
			}},
		},
	}, map[string]*oidc.IDTokenVerifier{
		issuer: newExternalAuthTestVerifier(issuer, clientID, jose.RS256, key.public, now),
	})
	if err != nil {
		t.Fatal(err)
	}

	raw := signExternalAuthTestToken(t, jose.RS256, key.private, jwt.Claims{
		Issuer:   issuer,
		Subject:  subject,
		Audience: jwt.Audience{clientID},
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(now.Add(time.Hour)),
	}, nil)

	tok, err := rs.Verify(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}

	anon := rs.Compile(yat.Identity{})
	if !anon(yat.NewPath("public/feed"), yat.SubAction) {
		t.Fatal("anonymous public access denied")
	}
	if anon(yat.NewPath("private/feed"), yat.SubAction) {
		t.Fatal("anonymous authenticated grant allowed")
	}

	authd := rs.Compile(yat.Identity{Token: tok})
	if !authd(yat.NewPath("public/feed"), yat.SubAction) {
		t.Fatal("authenticated public access denied")
	}
	if !authd(yat.NewPath("private/feed"), yat.SubAction) {
		t.Fatal("authenticated access denied")
	}
	if !authd(yat.NewPath("subject/feed"), yat.PubAction) {
		t.Fatal("subject grant denied")
	}
	if authd(yat.NewPath("subject/feed"), yat.SubAction) {
		t.Fatal("unexpected subject sub grant")
	}
	if authd(yat.NewPath("other/feed"), yat.PubAction) {
		t.Fatal("unexpected audience grant")
	}
}

func TestRuleSetVerifyRejectsUnknownIssuer(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	key := newExternalAuthTestKey(t, jose.RS256)

	rs, err := yat.NewRuleSet(nil, map[string]*oidc.IDTokenVerifier{
		"https://known.example": newExternalAuthTestVerifier(
			"https://known.example",
			"client-123",
			jose.RS256,
			key.public,
			now,
		),
	})
	if err != nil {
		t.Fatal(err)
	}

	raw := signExternalAuthTestToken(t, jose.RS256, key.private, jwt.Claims{
		Issuer:   "https://unknown.example",
		Subject:  "user-123",
		Audience: jwt.Audience{"client-123"},
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(now.Add(time.Hour)),
	}, nil)

	if _, err := rs.Verify(context.Background(), raw); err == nil {
		t.Fatal("no error")
	}
}

func TestRuleSetVerifyRejectsUnsupportedAlgorithm(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	raw := signExternalAuthTestToken(t, jose.HS256, []byte("0123456789abcdef0123456789abcdef"), jwt.Claims{
		Issuer:   "https://issuer.example",
		Subject:  "user-123",
		Audience: jwt.Audience{"client-123"},
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(now.Add(time.Hour)),
	}, nil)

	rs, err := yat.NewRuleSet(nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := rs.Verify(context.Background(), raw); err == nil {
		t.Fatal("no error")
	}
}

func TestRuleSetVerifyRejectsInvalidSignature(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	issuer := "https://issuer.example"
	clientID := "client-123"

	good := newExternalAuthTestKey(t, jose.RS256)
	bad := newExternalAuthTestKey(t, jose.RS256)

	rs, err := yat.NewRuleSet(nil, map[string]*oidc.IDTokenVerifier{
		issuer: newExternalAuthTestVerifier(issuer, clientID, jose.RS256, good.public, now),
	})
	if err != nil {
		t.Fatal(err)
	}

	raw := signExternalAuthTestToken(t, jose.RS256, bad.private, jwt.Claims{
		Issuer:   issuer,
		Subject:  "user-123",
		Audience: jwt.Audience{clientID},
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(now.Add(time.Hour)),
	}, nil)

	if _, err := rs.Verify(context.Background(), raw); err == nil {
		t.Fatal("no error")
	}
}

func TestRuleSetVerifyRejectsAudienceMismatch(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	issuer := "https://issuer.example"

	key := newExternalAuthTestKey(t, jose.RS256)
	rs, err := yat.NewRuleSet(nil, map[string]*oidc.IDTokenVerifier{
		issuer: newExternalAuthTestVerifier(issuer, "client-expected", jose.RS256, key.public, now),
	})
	if err != nil {
		t.Fatal(err)
	}

	raw := signExternalAuthTestToken(t, jose.RS256, key.private, jwt.Claims{
		Issuer:   issuer,
		Subject:  "user-123",
		Audience: jwt.Audience{"client-other"},
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(now.Add(time.Hour)),
	}, nil)

	if _, err := rs.Verify(context.Background(), raw); err == nil {
		t.Fatal("no error")
	}
}

type externalAuthTestKey struct {
	private any
	public  crypto.PublicKey
}

func newExternalAuthTestKey(t *testing.T, alg jose.SignatureAlgorithm) externalAuthTestKey {
	t.Helper()

	switch alg {
	case jose.RS256, jose.PS256:
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		return externalAuthTestKey{private: key, public: &key.PublicKey}

	case jose.ES256:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return externalAuthTestKey{private: key, public: &key.PublicKey}

	case jose.EdDSA:
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return externalAuthTestKey{private: private, public: public}

	default:
		t.Fatalf("unsupported algorithm %q", alg)
		return externalAuthTestKey{}
	}
}

func newExternalAuthTestVerifier(
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

func signExternalAuthTestToken(
	t *testing.T,
	alg jose.SignatureAlgorithm,
	key any,
	claims jwt.Claims,
	privateClaims map[string]any,
) string {
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
	return raw
}
