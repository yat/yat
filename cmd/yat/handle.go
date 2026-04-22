package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"time"

	"yat.io/yat"
	"yat.io/yat/cmd/yat/internal/flagset"
)

type HandleCmd struct {
	*ClientConfig
	File     string
	Empty    bool
	Limit    int
	Duration time.Duration
}

func (cmd *HandleCmd) AddFlags(flags *flagset.Set) {
	flags.String(&cmd.File, "file", "f")
	flags.Bool(&cmd.Empty, "empty", "e")
	flags.Int(&cmd.Limit, "limit", "n")
	flags.Duration(&cmd.Duration, "duration")
}

func (cmd *HandleCmd) Run(ctx context.Context, logger *slog.Logger, args []string) error {
	if len(args) != 1 {
		return usageError{
			Usage: "yat respond PATH",
			Topic: "respond",
		}
	}

	path, err := yat.ParsePath(args[0])
	if err != nil {
		return err
	}

	var data []byte
	if !cmd.Empty {
		if cmd.File == "-" || cmd.File == "/dev/stdin" {
			data, err = io.ReadAll(os.Stdin)
		} else {
			data, err = os.ReadFile(cmd.File)
		}
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

	if cmd.Duration > 0 {
		var cancel func()
		ctx, cancel = context.WithTimeout(ctx, cmd.Duration)
		defer cancel()
	}

	sub, err := yc.Handle(ctx, sel, func(context.Context, yat.Path, []byte) []byte {
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
