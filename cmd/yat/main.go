package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"

	"yat.io/yat"
	"yat.io/yat/cmd/yat/flagset"
)

type sharedConfig struct {
	Address     string     `json:"address"`
	LogLevel    slog.Level `json:"log-level"`
	TLSCAFile   string     `json:"tls-ca-file,omitempty"`
	TLSCertFile string     `json:"tls-cert-file,omitempty"`
	TLSKeyFile  string     `json:"tls-key-file,omitempty"`
}

type exitError struct {
	error
	Code int
}

func main() {
	err := run()

	var xe exitError
	if errors.As(err, &xe) {
		if xe.error != nil {
			fmt.Fprintln(os.Stderr, xe)
		}

		os.Exit(xe.Code)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "yat: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	shared := sharedConfig{
		Address:  "[::1]:8765",
		LogLevel: slog.LevelError,
	}

	if err := parseEnv(&shared); err != nil {
		return err
	}

	gflags := flagset.New()
	gflags.Text(&shared.LogLevel, "log-level")
	gflags.String(&shared.TLSCAFile, "tls-ca-file")
	gflags.String(&shared.TLSCertFile, "tls-cert-file")
	gflags.String(&shared.TLSKeyFile, "tls-key-file")
	gflags.String(&shared.Address, "address", "addr")

	args, err := gflags.Parse(os.Args[1:])
	if err != nil {
		return err
	}

	if len(args) == 0 {
		return errors.Join(
			helpCmd{os.Stderr}.Run(context.Background(), slog.Default(), shared, nil),
			exitError{Code: 2},
		)
	}

	var cmd interface {
		Run(ctx context.Context, logger *slog.Logger, cfg sharedConfig, args []string) error
	}

	name, args := gflags.Split()

	switch name {
	case "pub", "publish":
		cmd = &pubCmd{
			File: "/dev/stdin",
		}

	case "sub", "subscribe":
		cmd = &subCmd{}

	case "serve", "server":
		cmd = &serveCmd{}

	case "env", "environ", "environment":
		cmd = &envCmd{}

	case "help":
		cmd = &helpCmd{os.Stdout}

	default:
		return fmt.Errorf("%s: unknown command", name)
	}

	cflags := gflags.Clone()
	if fs, ok := cmd.(interface{ SetupFlags(*flagset.Set) }); ok {
		fs.SetupFlags(cflags)
	}

	// for convenient invocation, the syntax for yat commands is:
	// yat [shared flags] command [interleaved positional args, shared flags, and command flags]
	// the flags are parsed repeatedly until all flags are consumed and the positional args are adjacent

	for {
		fi := slices.IndexFunc(args, func(a string) bool {
			return strings.HasPrefix(a, "-")
		})

		if fi == -1 {
			break
		}

		trailing, err := cflags.Parse(args[fi:])
		if err != nil {
			return err
		}

		args = append(args[:fi], trailing...)
	}

	logger, err := setupLogger(shared)
	if err != nil {
		return err
	}

	logger.Debug("run",
		"command", name, "config", shared)

	return cmd.Run(context.Background(), logger, shared, args)
}

func (cfg sharedConfig) NewClient(logger *slog.Logger) (*yat.Client, error) {
	dial := func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", cfg.Address)
	}

	tlsConfig, err := cfg.loadClientTLSConfig()
	if err != nil {
		return nil, err
	}

	return yat.NewClient(dial, tlsConfig, yat.ClientConfig{
		Logger: logger,
	})
}

func (cfg sharedConfig) loadClientTLSConfig() (*tls.Config, error) {
	sn, _, err := net.SplitHostPort(cfg.Address)
	if err != nil {
		return nil, err
	}

	tc := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"yat"},
		ServerName: sn,
	}

	if len(cfg.TLSCertFile) > 0 && len(cfg.TLSKeyFile) > 0 {
		crt, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return nil, err
		}

		tc.Certificates = []tls.Certificate{crt}
	}

	if len(cfg.TLSCAFile) > 0 {
		ca, err := os.ReadFile(cfg.TLSCAFile)
		if err != nil {
			return nil, err
		}

		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(ca) {
			return nil, fmt.Errorf("load %s: no roots", cfg.TLSCAFile)
		}

		tc.RootCAs = roots
	}

	return tc, nil
}

func (cfg sharedConfig) loadServerTLSConfig() (*tls.Config, error) {
	tc := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"yat"},
	}

	crt, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return nil, err
	}

	tc.Certificates = []tls.Certificate{crt}

	if len(cfg.TLSCAFile) > 0 {
		ca, err := os.ReadFile(cfg.TLSCAFile)
		if err != nil {
			return nil, err
		}

		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(ca) {
			return nil, fmt.Errorf("load %s: no roots", cfg.TLSCAFile)
		}

		tc.ClientCAs = roots
		tc.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tc, nil
}

func parseEnv(shared *sharedConfig) error {
	if svr, ok := os.LookupEnv("YAT_ADDRESS"); ok {
		shared.Address = svr
	}

	if ll, ok := os.LookupEnv("YAT_LOG_LEVEL"); ok {
		if err := shared.LogLevel.UnmarshalText([]byte(ll)); err != nil {
			return fmt.Errorf("parse YAT_LOG_LEVEL: %v", err)
		}
	}

	if f, ok := os.LookupEnv("YAT_TLS_CA_FILE"); ok {
		shared.TLSCAFile = f
	}

	if f, ok := os.LookupEnv("YAT_TLS_CERT_FILE"); ok {
		shared.TLSCertFile = f
	}

	if f, ok := os.LookupEnv("YAT_TLS_KEY_FILE"); ok {
		shared.TLSKeyFile = f
	}

	return nil
}

func setupLogger(gc sharedConfig) (*slog.Logger, error) {
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: gc.LogLevel,

		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			switch {
			case a.Value.Kind() == slog.KindDuration:
				return slog.Float64(a.Key, a.Value.Duration().Seconds())

			default:
				return a
			}
		},
	})), nil
}
