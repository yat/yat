package main

import (
	"context"
	"log/slog"
	"net"

	"yat.io/yat"
	"yat.io/yat/cmd/yat/flagset"
)

type serveCmd struct {
	Address string
}

func (cmd serveCmd) Run(ctx context.Context, logger *slog.Logger, cfg sharedConfig, args []string) error {
	l, err := net.Listen("tcp", cmd.Address)
	if err != nil {
		return err
	}

	tlsConfig, err := cfg.loadServerTLSConfig()
	if err != nil {
		return err
	}

	svr, err := yat.NewServer(&yat.Bus{}, yat.ServerConfig{
		TLSConfig: tlsConfig,
		Logger:    logger,

		InsecureAllowAllActions: true,
	})

	if err != nil {
		return err
	}

	logger.Info("serve",
		"addr", l.Addr().String())

	return svr.Serve(l)
}

func (cmd *serveCmd) SetupFlags(fs *flagset.Set) {
	fs.String(&cmd.Address, "addr", "address")
}
