package cmd

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"
	"yat.io/yat"
)

// Config collects configuration for the yat command.
type Config struct {
	LogLevel  slog.Level
	TLSFiles  TLSFiles
	Server    string
	Token     string
	TokenFile string
}

// Env reads configuration from the yat environment variables.
//
//   - YAT_LOG_LEVEL
//   - YAT_TLS_CERT_FILE
//   - YAT_TLS_KEY_FILE
//   - YAT_TLS_CA_FILE
//   - YAT_TLS_CA_FILES
//   - YAT_SERVER
//   - YAT_TOKEN
//   - YAT_TOKEN_FILE
func EnvConfig() Config {
	ec := Config{
		TLSFiles: TLSFiles{
			CertFile: os.Getenv("YAT_TLS_CERT_FILE"),
			KeyFile:  os.Getenv("YAT_TLS_KEY_FILE"),
		},

		Server:    os.Getenv("YAT_SERVER"),
		Token:     os.Getenv("YAT_TOKEN"),
		TokenFile: os.Getenv("YAT_TOKEN_FILE"),
	}

	if ll, ok := os.LookupEnv("YAT_LOG_LEVEL"); ok {
		_ = ec.LogLevel.UnmarshalText([]byte(ll))
	}

	if name, ok := os.LookupEnv("YAT_TLS_CA_FILE"); ok {
		if name := strings.TrimSpace(name); name != "" {
			ec.TLSFiles.CAFiles = append(ec.TLSFiles.CAFiles, name)
		}
	}

	if names, ok := os.LookupEnv("YAT_TLS_CA_FILES"); ok {
		for name := range strings.SplitSeq(names, ",") {
			if name := strings.TrimSpace(name); name != "" {
				ec.TLSFiles.CAFiles = append(ec.TLSFiles.CAFiles, name)
			}
		}
	}

	return ec
}
func (c Config) NewClient(ctx context.Context, logger *slog.Logger) (*yat.Client, error) {
	if c.Server == "" {
		return nil, errors.New("server is not configured")
	}

	tcfg, watch, err := c.TLSFiles.ClientConfig()
	if err != nil {
		return nil, err
	}

	go watch(ctx, logger)

	cfg := yat.ClientConfig{
		Logger:    logger,
		TLSConfig: tcfg,
	}

	if c.Token != "" || c.TokenFile != "" {
		cfg.TokenSource = oauth2.ReuseTokenSource(nil, c.TokenSource())
	}

	return yat.NewClient(c.Server, cfg)
}

// TokenSource returns an oauth2 token source backed by ReadToken.
func (c Config) TokenSource() oauth2.TokenSource {
	return tokenSourceFunc(c.ReadToken)
}

// ReadToken reads an oauth2 token from the configuration.
func (c Config) ReadToken() (access *oauth2.Token, err error) {
	var raw []byte

	switch {
	case c.Token != "":
		raw = []byte(c.Token)

	case c.TokenFile != "":
		raw, err = os.ReadFile(c.TokenFile)

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

type tokenSourceFunc func() (*oauth2.Token, error)

func (f tokenSourceFunc) Token() (*oauth2.Token, error) { return f() }
