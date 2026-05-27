package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/goccy/go-yaml"
	"golang.org/x/oauth2"
	"yat.io/yat"
	"yat.io/yat/cmd"
	"yat.io/yat/cmd/yat/internal/flagset"
)

type ServeCmd struct {
	*cmd.Config

	BindAddr              string
	EndpointURL           url.URL
	ConfigFiles           []string
	LoginProvider         url.URL
	LoginClientID         string
	LoginClientSecretFile string
	RequireCert           bool
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
	flags.URL(&cmd.EndpointURL, "url")
	flags.Strings(&cmd.ConfigFiles, "config")
	flags.URL(&cmd.LoginProvider, "login-provider")
	flags.String(&cmd.LoginClientID, "login-client-id")
	flags.String(&cmd.LoginClientSecretFile, "login-client-secret-file")
	flags.Bool(&cmd.RequireCert, "tls-require-client-cert")
}

func (cmd ServeCmd) anyLoginConfig() bool {
	return cmd.LoginProvider != url.URL{} ||
		cmd.LoginClientID != "" ||
		os.Getenv("YAT_LOGIN_CLIENT_SECRET") != "" ||
		cmd.LoginClientSecretFile != ""
}

func (cmd *ServeCmd) Run(ctx context.Context, logger *slog.Logger, args []string) error {
	if len(args) != 0 {
		return usageError{
			Usage: "yat serve",
			Topic: "serve",
		}
	}

	if _, _, err := net.SplitHostPort(cmd.BindAddr); err != nil {
		return fmt.Errorf("bind %s: %v", cmd.BindAddr, err)
	}

	if len(cmd.TLSFiles.CAFiles) == 0 && cmd.RequireCert {
		logger.WarnContext(ctx, "no trust roots: all client connections will fail")
	}

	tcfg, watch, err := cmd.TLSFiles.ServerConfig(cmd.RequireCert)
	if err != nil {
		return err
	}

	go watch(ctx, logger)

	lis, err := tls.Listen("tcp", cmd.BindAddr, tcfg)
	if err != nil {
		return err
	}

	defer lis.Close()

	if cmd.EndpointURL == (url.URL{}) {
		host, _, _ := net.SplitHostPort(cmd.BindAddr)
		_, port, _ := net.SplitHostPort(lis.Addr().String())
		if a, _ := netip.ParseAddr(host); a.IsUnspecified() {
			return errors.New("this -bind requires a -url")
		}

		cmd.EndpointURL = url.URL{
			Scheme: "https",
			Host:   host,
		}

		switch {
		case port != "443":
			cmd.EndpointURL.Host = net.JoinHostPort(host, port)

		case strings.Contains(host, ":"):
			cmd.EndpointURL.Host = "[" + host + "]"
		}
	}

	if cmd.EndpointURL.Scheme != "https" {
		return errors.New("server URL scheme is not https")
	}

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

	var loginConfig *oauth2.Config
	var loginVerifier *oidc.IDTokenVerifier

	if cmd.anyLoginConfig() {
		if cmd.LoginProvider == (url.URL{}) {
			return errors.New("login provider is not configured")
		}

		if cmd.LoginClientID == "" {
			return errors.New("login client ID is not configured")
		}

		clientSecret := os.Getenv("YAT_LOGIN_CLIENT_SECRET")
		if clientSecret == "" && cmd.LoginClientSecretFile != "" {
			data, err := os.ReadFile(cmd.LoginClientSecretFile)
			if err != nil {
				return err
			}

			clientSecret = strings.TrimSpace(string(data))
		}

		if clientSecret == "" {
			return errors.New("login client secret is not configured")
		}

		p, err := oidc.NewProvider(ctx, cmd.LoginProvider.String())
		if err != nil {
			return err
		}

		loginConfig = &oauth2.Config{
			ClientID:     cmd.LoginClientID,
			ClientSecret: clientSecret,
			Endpoint:     p.Endpoint(),
			RedirectURL:  cmd.EndpointURL.JoinPath("login", "callback").String(),
			Scopes:       []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess, "profile", "email", "groups"},
		}

		loginVerifier = p.Verifier(&oidc.Config{
			ClientID: loginConfig.ClientID,
		})
	}

	ys, err := yat.NewServer(yat.ServerConfig{
		Logger:        logger,
		Rules:         rules,
		URL:           &cmd.EndpointURL,
		LoginConfig:   loginConfig,
		LoginVerifier: loginVerifier,
	})

	if err != nil {
		return err
	}

	hs := &http.Server{
		Handler: ys,
	}

	logger.InfoContext(ctx, "serve",
		"addr", lis.Addr().String(),
		"url", cmd.EndpointURL.String(),
		"rules", len(cfg.Rules),
		"login", loginConfig != nil)

	srvC := make(chan error, 1)
	go func() {
		err := hs.Serve(lis)
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
