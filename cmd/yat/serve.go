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
	TLSDir     string
	ConfigURLs []string
	AllowAll   bool
}

type serveConfig struct {
	Tag string `yaml:"tag"`

	Rules []struct {
		Token *struct {
			Any      bool   `yaml:"any"`
			Issuer   string `yaml:"issuer"`
			Audience string `yaml:"audience"`
			Subject  string `yaml:"subject"`
		} `yaml:"token"`

		Grants []struct {
			Path    string   `yaml:"path"`
			Actions []string `yaml:"actions"`
		} `yaml:"allow"`
	} `yaml:"rules"`
}

func (cmd *ServeCmd) AddFlags(flags *flagset.Set) {
	flags.String(&cmd.BindAddr, "bind")
	flags.String(&cmd.TLSDir, "tls-dir")
	flags.Strings(&cmd.ConfigURLs, "config")
	flags.Bool(&cmd.AllowAll, "allow-all")
}

func (cmd *ServeCmd) Run(ctx context.Context, logger *slog.Logger, args []string) error {
	if len(args) != 0 {
		return errors.New("serve doesn't take arguments")
	}

	if cmd.TLSDir == "" {
		return errors.New("missing required -tls-dir flag")
	}

	var cfg serveConfig
	for _, curl := range cmd.ConfigURLs {
		if err := loadServeConfig(&cfg, curl); err != nil {
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

	var rules *yat.RuleSet
	if cmd.AllowAll {
		rules = yat.AllowAll()
	}

	l, err := tls.Listen("tcp", cmd.BindAddr, td.TLSConfig())
	if err != nil {
		return err
	}

	if cfg.Tag != "" {
		logger = logger.With("tag", cfg.Tag)
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

func loadServeConfig(cfg *serveConfig, src string) error {
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

	var more serveConfig
	if err := yaml.Load(data, &more); err != nil {
		return err
	}

	if more.Tag != "" {
		cfg.Tag = more.Tag
	}

	cfg.Rules = append(cfg.Rules, more.Rules...)
	return nil
}

func (cfg *serveConfig) CompileRules() ([]yat.Rule, error) {
	var rules []yat.Rule
	for i, r := range cfg.Rules {
		var rule yat.Rule

		if spec := r.Token; spec != nil {
			if spec.Any {
				rule.Token = yat.AnyToken()
			} else {
				rule.Token = &yat.TokenSpec{
					Issuer:   spec.Issuer,
					Audience: spec.Audience,
					Subject:  spec.Subject,
				}
			}
		}

		for j, g := range r.Grants {
			scope := fmt.Sprintf("rules[%d].allow[%d]", i, j)
			path, _, err := yat.ParsePath(g.Path)

			if err != nil {
				return nil, fmt.Errorf("%s: %v", scope, err)
			}

			var actions []yat.Action
			for _, action := range g.Actions {
				switch yat.Action(action) {
				case yat.ActionPub, yat.ActionSub:
					actions = append(actions, yat.Action(action))
				default:
					return nil, fmt.Errorf("%s: unknown action", scope)
				}
			}

			rule.Grants = append(rule.Grants, yat.Grant{
				Path:    path,
				Actions: actions,
			})
		}

		rules = append(rules, rule)
	}

	return rules, nil
}
