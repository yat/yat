package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"

	"yat.io/yat"
	"yat.io/yat/cmd/yat/internal/flagset"
	"yat.io/yat/cmd/yat/internal/tlsdir"
)

type ServeCmd struct {
	BindAddr string
	TLSDir   string
}

func (cmd *ServeCmd) AddFlags(flags *flagset.Set) {
	flags.String(&cmd.BindAddr, "bind")
	flags.String(&cmd.TLSDir, "tls-dir")
}

func (cmd *ServeCmd) Run(ctx context.Context, logger *slog.Logger, args []string) error {
	if cmd.TLSDir == "" {
		return errors.New("missing required -tls-dir flag")
	}

	baseConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"y0"},
	}

	dc, err := tlsdir.LoadServerConfig(cmd.TLSDir, baseConfig)
	if err != nil {
		return err
	}

	go dc.Watch(ctx, logger)

	l, err := tls.Listen("tcp", cmd.BindAddr, dc.TLSConfig())
	if err != nil {
		return err
	}

	svr, err := yat.NewServer(yat.NewRouter(), yat.ServerConfig{
		Logger: logger,
	})

	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()

		logger.InfoContext(ctx, "shutdown",
			"cause", context.Cause(ctx))

		l.Close()
	}()

	logger.InfoContext(ctx, "serve",
		"addr", l.Addr().String())

	err = svr.Serve(l)
	if errors.Is(err, net.ErrClosed) {
		err = nil
	}

	return err
}
