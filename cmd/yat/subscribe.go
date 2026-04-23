package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"time"

	"yat.io/yat"
	"yat.io/yat/cmd"
	"yat.io/yat/cmd/yat/internal/flagset"
)

type SubscribeCmd struct {
	*cmd.Config

	Limit    int
	Duration time.Duration
	Raw      bool
}

func (cmd *SubscribeCmd) AddFlags(flags *flagset.Set) {
	flags.Int(&cmd.Limit, "limit", "n")
	flags.Duration(&cmd.Duration, "duration", "d")
	flags.Bool(&cmd.Raw, "raw")
}

func (cmd *SubscribeCmd) Run(ctx context.Context, logger *slog.Logger, args []string) error {
	if len(args) != 1 {
		return usageError{
			Usage: "yat subscribe PATH",
			Topic: "subscribe",
		}
	}

	yc, err := cmd.NewClient(ctx, logger)
	if err != nil {
		return err
	}

	defer yc.Close()

	cb := func(_ context.Context, m yat.Msg) {
		var err error
		if cmd.Raw {
			_, err = os.Stdout.Write(m.Data)
		} else {
			err = json.NewEncoder(os.Stdout).Encode(m)
		}

		if err != nil {
			logger.ErrorContext(ctx, "write failed", "error", err)
		}
	}

	path, err := yat.ParsePath(args[0])
	if err != nil {
		return err
	}

	sel := yat.Sel{
		Path:  path,
		Limit: cmd.Limit,
	}

	if cmd.Duration > 0 {
		var cancel func()
		ctx, cancel = context.WithTimeout(ctx, cmd.Duration)
		defer cancel()
	}

	sub, err := yc.Subscribe(ctx, sel, cb)
	if err != nil {
		return err
	}

	select {
	case <-ctx.Done():
		if ctx.Err() == context.DeadlineExceeded {
			return nil
		}
		return ctx.Err()

	case <-sub.Done():
		return nil
	}
}
