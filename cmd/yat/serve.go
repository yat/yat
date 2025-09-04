package main

import (
	"context"
	"log/slog"
	"net"

	"yat.io/yat"
	"yat.io/yat/cmd/yat/flagset"
)

// FIX: support ACME
type serveCmd struct {
	Address string
}

func (cmd serveCmd) Run(ctx context.Context, logger *slog.Logger, cfg sharedConfig, args []string) error {
	l, err := net.Listen("tcp", cmd.Address)
	if err != nil {
		return err
	}

	svr := yat.NewServer(&yat.Bus{}, yat.ServerConfig{
		Logger: logger,

		InsecureAllowAllActions: true,
		InsecureAllowNoTLS:      true,
	})

	logger.Info("serve",
		"addr", l.Addr().String())

	return svr.Serve(l)
}

func (cmd *serveCmd) SetupFlags(fs *flagset.Set) {
	fs.String(&cmd.Address, "addr", "address")
}
