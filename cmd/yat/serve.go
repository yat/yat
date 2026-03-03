package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"

	"golang.org/x/net/http2"
	"yat.io/yat"
	"yat.io/yat/cmd/yat/internal/flagset"
	"yat.io/yat/cmd/yat/internal/tlsdir"
)

type ServeCmd struct {
	BindAddr string
	TLSDir   string
	AllowAll bool
}

func (cmd *ServeCmd) AddFlags(flags *flagset.Set) {
	flags.String(&cmd.BindAddr, "bind")
	flags.String(&cmd.TLSDir, "tls-dir")
	flags.Bool(&cmd.AllowAll, "allow-all")
}

func (cmd *ServeCmd) Run(ctx context.Context, logger *slog.Logger, args []string) error {
	if len(args) != 0 {
		return usageError{
			Usage: "yat serve",
			Topic: "serve",
		}
	}

	if cmd.TLSDir == "" {
		return errors.New("missing required -tls-dir flag")
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

	var rules *yat.RuleSet
	if cmd.AllowAll {
		rules = yat.AllowAll()
	}

	l, err := tls.Listen("tcp", cmd.BindAddr, td.TLSConfig())
	if err != nil {
		return err
	}

	ys, err := yat.NewServer(yat.NewRouter(), yat.ServerConfig{
		Logger: logger,
		Rules:  rules,
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
