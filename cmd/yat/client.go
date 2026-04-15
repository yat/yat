package main

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"os"

	"yat.io/yat"
)

type ClientConfig struct {
	*SharedConfig
	Server    string
	Token     string
	TokenFile string
}

const clientALPN = "y0"

func (cc ClientConfig) NewClient(ctx context.Context, logger *slog.Logger) (*yat.Client, error) {
	addr, serverName, err := cc.parseAddr()
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

	if cc.TLSDir != "" {
		td, err := cc.LoadTLSConfig(baseConfig)
		if err != nil {
			return nil, err
		}

		getConfig = td.ClientConfig
		go td.Watch(ctx, logger)
	}

	dial := func(ctx context.Context) (net.Conn, error) {
		return (&tls.Dialer{Config: getConfig()}).DialContext(ctx, "tcp", addr)
	}

	cfg := yat.ClientConfig{
		Logger: logger,
	}

	if cc.Token != "" {
		cfg.GetToken = func(context.Context) ([]byte, error) {
			return []byte(cc.Token), nil
		}
	}

	if cc.TokenFile != "" && cfg.GetToken == nil {
		cfg.GetToken = func(context.Context) ([]byte, error) {
			return os.ReadFile(cc.TokenFile)
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
