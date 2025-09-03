package main

import (
	"context"
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
	LogLevel slog.Level

	TLSCAFile   string
	TLSCertFile string
	TLSKeyFile  string

	// client flags
	Server string
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
		panic(err)
	}
}

func run() error {
	shared := sharedConfig{
		LogLevel: slog.LevelError,
		Server:   "[::1]:8765",
	}

	if err := parseEnv(&shared); err != nil {
		return err
	}

	gflags := flagset.New()
	gflags.Text(&shared.LogLevel, "log-level")
	gflags.String(&shared.TLSCAFile, "tls-ca-file")
	gflags.String(&shared.TLSCertFile, "tls-cert-file")
	gflags.String(&shared.TLSKeyFile, "tls-key-file")
	gflags.String(&shared.Server, "server")

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
		cmd = &serveCmd{
			Address: "[::1]:8765",
		}

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

	logger.Debug("logger initialized",
		"log-level", shared.LogLevel)

	logger.Debug("run",
		"command", name)

	return cmd.Run(context.Background(), logger, shared, args)
}

func (cfg sharedConfig) NewClient(logger *slog.Logger) *yat.Client {
	dial := func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", cfg.Server)
	}

	// FIX: configure TLS
	return yat.NewClient(dial, yat.ClientConfig{
		Logger: logger,
	})
}

func parseEnv(shared *sharedConfig) error {
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

	if svr, ok := os.LookupEnv("YAT_SERVER"); ok {
		shared.Server = svr
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
