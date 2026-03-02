package main

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"os"

	"yat.io/yat"
	"yat.io/yat/cmd/yat/internal/tlsdir"
)

type ClientConfig struct {
	Server  string
	JWTFile string
	TLSDir  string
}

const clientALPN = "y0"

func (cmd ClientConfig) NewClient(ctx context.Context, logger *slog.Logger) (*yat.Client, error) {
	addr, serverName, err := cmd.parseAddr()
	if err != nil {
		return nil, err
	}

	baseConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{clientALPN},
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

	cfg := yat.ClientConfig{
		Logger: logger,
	}

	if cmd.JWTFile != "" {
		cfg.GetToken = func(context.Context) ([]byte, error) {
			return os.ReadFile(cmd.JWTFile)
		}
	}

	return yat.NewClient(dial, cfg)
}

func (cmd ClientConfig) parseAddr() (addr, serverName string, err error) {
	if serverName, _, err = net.SplitHostPort(cmd.Server); err == nil {
		addr = cmd.Server
		return
	}

	cmd.Server += ":443"
	if serverName, _, err = net.SplitHostPort(cmd.Server); err == nil {
		addr = cmd.Server
	}

	return
}
