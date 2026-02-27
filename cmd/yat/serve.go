package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"

	"go.yaml.in/yaml/v4"
	"golang.org/x/net/http2"
	"yat.io/yat"
	"yat.io/yat/cmd/yat/internal/flagset"
	"yat.io/yat/cmd/yat/internal/tlsdir"
)

type ServeCmd struct {
	BindAddr   string
	ConfigURLs []string
	TLSDir     string
}

type serverConfig struct {
	Tag string `yaml:"tag"`
}

func (cmd *ServeCmd) AddFlags(flags *flagset.Set) {
	flags.String(&cmd.BindAddr, "bind")
	flags.Strings(&cmd.ConfigURLs, "config")
	flags.String(&cmd.TLSDir, "tls-dir")
}

func (cmd *ServeCmd) Run(ctx context.Context, logger *slog.Logger, args []string) error {
	if cmd.TLSDir == "" {
		return errors.New("missing required -tls-dir flag")
	}

	var cfg serverConfig
	for _, curl := range cmd.ConfigURLs {
		if err := loadServerConfig(&cfg, curl); err != nil {
			return err
		}
	}

	baseTLSConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{clientALPN, "h2", "http/1.1"},
	}

	td, err := tlsdir.LoadServerConfig(cmd.TLSDir, baseTLSConfig)
	if err != nil {
		return err
	}

	go td.Watch(ctx, logger)

	l, err := tls.Listen("tcp", cmd.BindAddr, td.TLSConfig())
	if err != nil {
		return err
	}

	if cfg.Tag != "" {
		logger = logger.With("tag", cfg.Tag)
	}

	ys, err := yat.NewServer(yat.NewRouter(), yat.ServerConfig{
		Logger: logger,
	})

	if err != nil {
		return err
	}

	hs := &http.Server{
		TLSConfig: baseTLSConfig.Clone(),
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){
			"y0": func(_ *http.Server, conn *tls.Conn, _ http.Handler) {
				ys.ServeConn(ctx, conn)
			},
		},
	}

	if err := http2.ConfigureServer(hs, &http2.Server{}); err != nil {
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

	err = hs.Serve(l)
	if errors.Is(err, net.ErrClosed) {
		err = nil
	}

	return err
}

func loadServerConfig(cfg *serverConfig, src string) error {
	su, err := url.Parse(src)
	if err != nil {
		return err
	}

	var data []byte
	switch su.Scheme {
	case "file", "":
		data, err = os.ReadFile(su.Path)

	default:
		err = fmt.Errorf("unsupported scheme: %s", su.Scheme)
	}

	if err != nil {
		return err
	}

	return yaml.Load(data, cfg)
}
