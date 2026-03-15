package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"yat.io/yat"
	"yat.io/yat/cmd/yat/internal/flagset"
)

type RespondCmd struct {
	*ClientConfig
	File     string
	Empty    bool
	Group    string
	Limit    int
	Duration time.Duration
}

func (cmd *RespondCmd) AddFlags(flags *flagset.Set) {
	flags.String(&cmd.File, "file", "f")
	flags.Bool(&cmd.Empty, "empty", "e")
	flags.String(&cmd.Group, "group", "g")
	flags.Int(&cmd.Limit, "limit", "n")
	flags.Duration(&cmd.Duration, "duration")
}

func (cmd *RespondCmd) Run(ctx context.Context, logger *slog.Logger, args []string) error {
	if len(args) != 1 {
		return usageError{
			Usage: "yat respond PATH",
			Topic: "respond",
		}
	}

	path, _, err := yat.ParsePath(args[0])
	if err != nil {
		return err
	}

	var data []byte
	if !cmd.Empty {
		in := cmd.File
		if in == "-" {
			in = "/dev/stdin"
		}

		data, err = os.ReadFile(in)
		if err != nil {
			return err
		}
	}

	yc, err := cmd.NewClient(ctx, logger)
	if err != nil {
		return err
	}

	defer yc.Close()

	sel := yat.Sel{
		Path:  path,
		Limit: cmd.Limit,
	}

	if cmd.Group != "" {
		sel.Group = yat.NewGroup(cmd.Group)
	}

	if cmd.Duration > 0 {
		var cancel func()
		ctx, cancel = context.WithTimeout(ctx, cmd.Duration)
		defer cancel()
	}

	sub, err := yc.Respond(sel, func(_ context.Context, _ yat.Msg) []byte {
		return data
	})

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
