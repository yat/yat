package main

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"

	"yat.io/yat"
	"yat.io/yat/cmd/yat/internal/tlsdir"
)

type ClientConfig struct {
	Addr   string
	TLSDir string
}

func (cmd ClientConfig) NewClient(ctx context.Context, logger *slog.Logger) (*yat.Client, error) {
	addr, serverName, err := cmd.parseAddr()
	if err != nil {
		return nil, err
	}

	baseConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"y0"},
		ServerName: serverName,
	}

	getConfig := func() *tls.Config {
		return baseConfig
	}

	if cmd.TLSDir != "" {
		d, err := tlsdir.LoadClientConfig(cmd.TLSDir, baseConfig)
		if err != nil {
			return nil, err
		}

		getConfig = d.TLSConfig
		go d.Watch(ctx, logger)
	}

	dial := func(ctx context.Context) (net.Conn, error) {
		return (&tls.Dialer{Config: getConfig()}).DialContext(ctx, "tcp", addr)
	}

	return yat.NewClient(dial, yat.ClientConfig{
		Logger: logger,
	})
}

func (cmd ClientConfig) parseAddr() (addr, serverName string, err error) {
	if serverName, _, err = net.SplitHostPort(cmd.Addr); err == nil {
		addr = cmd.Addr
		return
	}

	cmd.Addr += ":443"
	if serverName, _, err = net.SplitHostPort(cmd.Addr); err == nil {
		addr = cmd.Addr
	}

	return
}
