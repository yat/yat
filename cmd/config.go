package cmd

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"

	"yat.io/yat"
)

// Config collects configuration for the yat command.
type Config struct {
	TLSFiles  TLSFiles
	Server    string
	Token     string
	TokenFile string
}

// Env reads configuration from the yat environment variables.
//
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

	switch {
	case c.Token != "":
		token := strings.TrimSpace(c.Token)
		cfg.GetCreds = yat.BearerToken(token)

	case c.TokenFile != "":
		cfg.GetCreds = yat.TokenFile(c.TokenFile)
	}

	return yat.NewClient(c.Server, cfg)
}
