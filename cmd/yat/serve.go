package main

import (
	"context"
	"log/slog"
	"net"
	"sync"

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

	logger.Info("serve",
		"addr", l.Addr().String())

	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}

		wg.Go(func() {
			yat.Serve(ctx, conn, &yat.Bus{}, yat.ServerConfig{
				Logger: logger,

				InsecureAllowAllActions: true,
				InsecureAllowNoTLS:      true,
			})
		})
	}
}

func (cmd *serveCmd) SetupFlags(fs *flagset.Set) {
	fs.String(&cmd.Address, "addr", "address")
}
