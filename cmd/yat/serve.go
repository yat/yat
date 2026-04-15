package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"

	"github.com/goccy/go-yaml"
	"golang.org/x/net/http2"
	"yat.io/yat"
	"yat.io/yat/cmd/yat/internal/flagset"
)

type ServeCmd struct {
	*SharedConfig
	BindAddr    string
	ConfigFiles []string
}

type serverConfig struct {
	serverConfigHeader
	serverConfigRuleSet
}

type serverConfigHeader struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
}

type serverConfigRuleSet struct {
	Rules []yat.Rule `json:"rules"`
}

func (cmd *ServeCmd) AddFlags(flags *flagset.Set) {
	flags.String(&cmd.BindAddr, "bind")
	flags.Strings(&cmd.ConfigFiles, "config")
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

	td, err := cmd.LoadTLSConfig(baseTLSConfig)
	if err != nil {
		return err
	}

	go td.Watch(ctx, logger)

	var cfg serverConfig
	for _, name := range cmd.ConfigFiles {
		data, err := os.ReadFile(name)
		if err != nil {
			return err
		}

		if err := loadServerConfig(&cfg, data); err != nil {
			return fmt.Errorf("load %s: %v", name, err)
		}
	}

	rs, err := yat.NewRuleSet(ctx, cfg.Rules)
	if err != nil {
		return err
	}

	l, err := tls.Listen("tcp", cmd.BindAddr, td.ServerConfig())
	if err != nil {
		return err
	}

	ys, err := yat.NewServer(yat.NewRouter(), yat.ServerConfig{
		Logger: logger,
		Rules:  rs,
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

func loadServerConfig(cfg *serverConfig, data []byte) error {
	// only the first doc for now
	var hdr serverConfigHeader
	if err := yaml.Unmarshal(data, &hdr); err != nil {
		return err
	}

	if hdr.APIVersion != "yat.io/v1alpha1" {
		return errors.New("invalid apiVersion")
	}

	if hdr.Kind == "" {
		return errors.New("missing kind")
	}

	switch hdr.Kind {
	case "RuleSet":
		var ruleSet serverConfigRuleSet
		if err := yaml.Unmarshal(data, &ruleSet); err != nil {
			return err
		}
		cfg.Rules = append(cfg.Rules, ruleSet.Rules...)

	default:
		return fmt.Errorf("unknown type %s.%s", hdr.APIVersion, hdr.Kind)
	}

	return nil
}
