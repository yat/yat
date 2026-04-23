package main

import (
	"context"
	"errors"
	"log/slog"
	"os"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"
	"yat.io/yat"
	"yat.io/yat/cmd"
)

type SharedConfig struct {
	LogLevel slog.Level
	TLSFiles cmd.TLSFiles
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

	tcfg, err := cc.TLSFiles.ClientConfig()
	if err != nil {
		return nil, err
	}

	cfg := yat.ClientConfig{
		Logger:    logger,
		TLSConfig: tcfg,
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
