package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"yat.io/yat"
	"yat.io/yat/internal/flagset"
)

type RespondCmd struct {
	Path     string
	File     string
	Empty    bool
	Limit    int
	Duration time.Duration
}

func (cmd RespondCmd) Run(ctx context.Context, logger *slog.Logger, cfg SharedConfig, args []string) error {
	if len(args) != 1 {
		return usageError{
			Usage: "yat respond [flags] PATH",
			Topic: "respond",
		}
	}

	cmd.Path = args[0]
	if len(cmd.File) == 0 {
		cmd.File = "/dev/stdin"
	}

	if err := cmd.run(ctx, logger, cfg); err != nil {
		return fmt.Errorf("yat respond %s: %v", cmd.Path, err)
	}

	return nil
}

func (cmd RespondCmd) run(ctx context.Context, _ *slog.Logger, cfg SharedConfig) error {
	var data []byte
	var err error

	if !cmd.Empty {
		data, err = os.ReadFile(cmd.File)
		if err != nil {
			return err
		}
	}

	path, _, err := yat.ParsePath([]byte(cmd.Path))
	if err != nil {
		return err
	}

	sel := yat.Sel{
		Path: path,
	}

	if cmd.Limit > 0 {
		sel.Limit = cmd.Limit
	}

	conn, err := cfg.Dial(ctx)
	if err != nil {
		return err
	}

	cc := yat.NewConn(conn)
	defer cc.Close()

	sub, err := cc.Subscribe(sel, func(m yat.Msg) {
		if m.Reply.IsZero() {
			return
		}

		res := yat.Msg{
			Path: m.Reply,
			Data: data,
		}

		if err := cc.Publish(res); err != nil {
			panic(err)
		}
	})

	if err != nil {
		return err
	}

	var elapsed <-chan time.Time
	if cmd.Duration > 0 {
		elapsed = time.After(cmd.Duration)
	}

	select {
	case <-ctx.Done():
		return ctx.Err()

	case <-cc.Done():
		return cc.Err()

	case <-sub.Done():
		return nil

	case <-elapsed:
		return nil
	}
}

func (cmd *RespondCmd) Flags() *flagset.Set {
	flags := flagset.New()
	flags.String(&cmd.File, "file", "f")
	flags.Bool(&cmd.Empty, "empty", "e")
	flags.Int(&cmd.Limit, "limit", "n")
	flags.Duration(&cmd.Duration, "duration")
	return flags
}
