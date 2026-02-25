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

type ClientCmd struct {
	Addr   string
	TLSDir string
}

func (cmd *ClientCmd) AddFlags(flags *flagset.Set) {
	flags.String(&cmd.Addr, "addr")
	flags.String(&cmd.TLSDir, "tls-dir")
}

func (cmd *ClientCmd) newClient(ctx context.Context, logger *slog.Logger) (*yat.Client, error) {
	if cmd.TLSDir == "" {
		return nil, errors.New("missing required -tls-dir flag")
	}

	host, _, err := net.SplitHostPort(cmd.Addr)
	if err != nil {
		return nil, err
	}

	baseConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"y0"},
		ServerName: host,
	}

	dc, err := tlsdir.LoadClientConfig(cmd.TLSDir, baseConfig)
	if err != nil {
		return nil, err
	}

	go dc.Watch(ctx, logger)

	dial := func(ctx context.Context) (net.Conn, error) {
		return (&tls.Dialer{Config: dc.TLSConfig()}).DialContext(ctx, "tcp", cmd.Addr)
	}

	return yat.NewClient(dial, yat.ClientConfig{
		Logger: logger,
	})
}
