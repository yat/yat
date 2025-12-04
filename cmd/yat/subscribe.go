package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"yat.io/yat"
	"yat.io/yat/internal/flagset"
)

type SubscribeCmd struct {
	Path     string
	Limit    int
	Duration time.Duration
	Format   string
}

func (cmd SubscribeCmd) Run(ctx context.Context, logger *slog.Logger, cfg SharedConfig, args []string) error {
	if len(args) != 1 {
		return usageError{
			Usage: "yat subscribe [flags] PATH",
			Topic: "subscribe",
		}
	}

	cmd.Path = args[0]

	if err := cmd.run(ctx, logger, cfg); err != nil {
		return fmt.Errorf("yat subscribe %s: %v", cmd.Path, err)
	}

	return nil
}

func (cmd SubscribeCmd) run(ctx context.Context, _ *slog.Logger, cfg SharedConfig) error {
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
		switch cmd.Format {
		case "json", "jsonl":
			if err := json.NewEncoder(os.Stdout).Encode(m); err != nil {
				panic(err)
			}

		default:
			if _, err := os.Stdout.Write(m.Data); err != nil {
				panic(err)
			}
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

func (cmd *SubscribeCmd) Flags() *flagset.Set {
	flags := flagset.New()
	flags.Int(&cmd.Limit, "limit", "n")
	flags.Duration(&cmd.Duration, "duration")
	flags.String(&cmd.Format, "format")
	return flags
}
