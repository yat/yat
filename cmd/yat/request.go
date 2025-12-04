package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"yat.io/yat"
	"yat.io/yat/internal/flagset"
)

type RequestCmd struct {
	Path    string
	File    string
	Empty   bool
	Timeout time.Duration
}

func (cmd RequestCmd) Run(ctx context.Context, logger *slog.Logger, cfg SharedConfig, args []string) error {
	if len(args) != 1 {
		return usageError{
			Usage: "yat request [flags] PATH",
			Topic: "request",
		}
	}

	cmd.Path = args[0]
	if len(cmd.File) == 0 {
		cmd.File = "/dev/stdin"
	}

	if err := cmd.run(ctx, logger, cfg); err != nil {
		return fmt.Errorf("yat request %s: %v", cmd.Path, err)
	}

	return nil
}

func (cmd RequestCmd) run(ctx context.Context, _ *slog.Logger, cfg SharedConfig) error {
	var data []byte
	var err error

	if !cmd.Empty {
		data, err = os.ReadFile(cmd.File)
		if err != nil {
			return err
		}
	}

	path, wild, err := yat.ParsePath([]byte(cmd.Path))
	if err != nil {
		return err
	}

	if wild {
		return errors.New("wildcard path")
	}

	conn, err := cfg.Dial(ctx)
	if err != nil {
		return err
	}

	cc := yat.NewConn(conn)
	defer cc.Close()

	var cancel func()
	if cmd.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, cmd.Timeout)
		defer cancel()
	}

	err = cc.Request(ctx, path, data, func(m yat.Msg) error {
		_, err := os.Stdout.Write(m.Data)
		return err
	})

	if err == context.DeadlineExceeded {
		err = errors.New("timeout")
	}

	return err
}

func (cmd *RequestCmd) Flags() *flagset.Set {
	flags := flagset.New()
	flags.String(&cmd.File, "file", "f")
	flags.Bool(&cmd.Empty, "empty", "e")
	flags.Duration(&cmd.Timeout, "timeout")
	return flags
}
