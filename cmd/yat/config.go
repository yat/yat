package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"
	"yat.io/yat"
)

type SharedConfig struct {
	LogLevel    slog.Level
	TLSCertFile string
	TLSKeyFile  string
	TLSCAFiles  []string
}

func (sc SharedConfig) LoadTLSConfig() (chains []tls.Certificate, roots *x509.CertPool, err error) {
	haveCertFile := sc.TLSCertFile != ""
	haveKeyFile := sc.TLSKeyFile != ""
	haveCAFiles := len(sc.TLSCAFiles) > 0

	if haveCertFile != haveKeyFile {
		err = errors.New("-tls-cert-file and -tls-key-file must be set together")
		return
	}

	if haveCertFile {
		crt, err := tls.LoadX509KeyPair(sc.TLSCertFile, sc.TLSKeyFile)
		if err != nil {
			return nil, nil, err
		}

		chains = []tls.Certificate{crt}
	}

	if haveCAFiles {
		roots = x509.NewCertPool()
		for _, name := range sc.TLSCAFiles {
			raw, err := os.ReadFile(name)
			if err != nil {
				return nil, nil, err
			}

			if !roots.AppendCertsFromPEM(raw) {
				return nil, nil, fmt.Errorf("parse %s: no roots", name)
			}
		}
	}

	return
}

type ClientConfig struct {
	*SharedConfig
	Server      string
	StaticToken string
	TokenFile   string
}

func (cc ClientConfig) NewClient(ctx context.Context, logger *slog.Logger) (*yat.Client, error) {
	if cc.Server == "" {
		return nil, errors.New("server is not configured")
	}

	cfg := yat.ClientConfig{
		Logger: logger,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
		},
	}

	chains, roots, err := cc.LoadTLSConfig()
	if err != nil {
		return nil, err
	}

	if len(chains) > 0 {
		cfg.TLSConfig.Certificates = chains
	}

	if roots != nil {
		cfg.TLSConfig.RootCAs = roots
	}

	if cc.StaticToken != "" || cc.TokenFile != "" {
		cfg.TokenSource = oauth2.ReuseTokenSource(nil, cc)
	}

	return yat.NewClient(cc.Server, cfg)
}

// Token implements [oauth2.TokenSource].
func (cc ClientConfig) Token() (access *oauth2.Token, err error) {
	var raw []byte

	switch {
	case cc.TokenFile != "":
		raw, err = os.ReadFile(cc.TokenFile)

	case cc.StaticToken != "":
		raw = []byte(cc.StaticToken)

	default:
		err = errors.New("no token")
	}

	if err != nil {
		return
	}

	jt, err := jwt.ParseSigned(string(raw), []jose.SignatureAlgorithm{jose.ES256, jose.PS256, jose.RS256})
	if err != nil {
		return
	}

	var claims jwt.Claims
	if err := jt.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, err
	}

	access = &oauth2.Token{
		AccessToken: string(raw),
		TokenType:   "Bearer",
		Expiry:      claims.Expiry.Time(),
	}

	return
}
