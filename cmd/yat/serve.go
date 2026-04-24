package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/goccy/go-yaml"
	"yat.io/yat"
	"yat.io/yat/cmd"
	"yat.io/yat/cmd/yat/internal/flagset"
)

type ServeCmd struct {
	*cmd.Config

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

	tcfg, watch, err := cmd.TLSFiles.ServerConfig()
	if err != nil {
		return err
	}
	go watch(ctx, logger)

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

	rules, err := yat.NewRuleSet(ctx, cfg.Rules)
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

	l, err := tls.Listen("tcp", cmd.BindAddr, tcfg)
	if err != nil {
		return err
	}

	hs := &http.Server{
		Handler: ys,
	}

	logger.InfoContext(ctx, "serve",
		"addr", l.Addr().String(),
		"rules", len(cfg.Rules))

	srvC := make(chan error, 1)
	go func() {
		err := hs.Serve(l)
		if err == http.ErrServerClosed {
			err = nil
		}
		srvC <- err
	}()

	select {
	case err := <-srvC:
		return err

	case <-ctx.Done():
	}

	logger.InfoContext(ctx, "shutdown",
		"cause", context.Cause(ctx))

	// give the server a few seconds to shut down
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := hs.Shutdown(sctx); err != nil {
		return err
	}

	return <-srvC
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
		if err := yaml.UnmarshalWithOptions(data, &ruleSet, yaml.UseJSONUnmarshaler()); err != nil {
			return err
		}
		cfg.Rules = append(cfg.Rules, ruleSet.Rules...)

	default:
		return fmt.Errorf("unknown type %s.%s", hdr.APIVersion, hdr.Kind)
	}

	return nil
}
