package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"path/filepath"

	"yat.io/yat"
	"yat.io/yat/cmd/yat/flagset"
	"yat.io/yat/dev"
)

type serveCmd struct {
	DevDir string

	InsecureAllowAllActions bool
}

func (cmd serveCmd) Run(ctx context.Context, logger *slog.Logger, cfg sharedConfig, args []string) error {
	l, err := net.Listen("tcp", cfg.Address)
	if err != nil {
		return err
	}

	if cmd.DevDir != "" {
		hasTLSConfig := len(cfg.TLSCAFile) > 0 ||
			len(cfg.TLSCertFile) > 0 ||
			len(cfg.TLSKeyFile) > 0

		if hasTLSConfig {
			return errors.New("-dev can't be combined with -tls flags or YAT_TLS environment variables")
		}

		host, _, err := net.SplitHostPort(cfg.Address)
		if err != nil {
			return err
		}

		generated, err := dev.GenerateCreds(cmd.DevDir, host)
		if err != nil {
			return err
		}

		if generated {
			logger.InfoContext(ctx, "dev creds initialized", "dir", cmd.DevDir)
		}

		cfg.TLSCAFile = filepath.Join(cmd.DevDir, "tls/ca.crt")
		cfg.TLSCertFile = filepath.Join(cmd.DevDir, "tls/server.crt")
		cfg.TLSKeyFile = filepath.Join(cmd.DevDir, "tls/server.key")
	}

	tlsConfig, err := cfg.loadServerTLSConfig()
	if err != nil {
		return err
	}

	svr, err := yat.NewServer(&yat.Bus{}, yat.ServerConfig{
		TLSConfig: tlsConfig,
		Logger:    logger,

		InsecureAllowAllActions: cmd.InsecureAllowAllActions,
	})

	if err != nil {
		return err
	}

	logger.Info("serve",
		"address", l.Addr().String())

	return svr.Serve(l)
}

func (cmd *serveCmd) SetupFlags(fs *flagset.Set) {
	fs.String(&cmd.DevDir, "dev")
	fs.Bool(&cmd.InsecureAllowAllActions, "insecure-allow-all-actions")
}
