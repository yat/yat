package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"time"

	"yat.io/yat"
	"yat.io/yat/cmd"
	"yat.io/yat/cmd/yat/internal/flagset"
)

type PostCmd struct {
	*cmd.Config

	File     string
	Empty    bool
	Raw      bool
	Limit    int
	Duration time.Duration
	Timeout  time.Duration
}

func (cmd *PostCmd) AddFlags(flags *flagset.Set) {
	flags.String(&cmd.File, "file", "f")
	flags.Bool(&cmd.Empty, "empty", "e")
	flags.Bool(&cmd.Raw, "raw")
	flags.Int(&cmd.Limit, "limit", "n")
	flags.Duration(&cmd.Duration, "duration", "d")
	flags.Duration(&cmd.Timeout, "timeout", "t")
}

func (cmd *PostCmd) Run(ctx context.Context, logger *slog.Logger, args []string) error {
	if len(args) != 1 {
		return usageError{
			Usage: "yat request PATH",
			Topic: "request",
		}
	}

	path, err := yat.ParsePath(args[0])
	if err != nil {
		return err
	}

	data, err := loadData(cmd.File, cmd.Empty)
	if err != nil {
		return err
	}

	if cmd.Limit < 0 {
		return errNegLimit
	}

	if cmd.Duration < 0 {
		return errNegDuration
	}

	if cmd.Timeout < 0 {
		return errNegTimeout
	}

	errDuration := errors.New("duration elapsed")
	if cmd.Timeout > 0 && cmd.Duration > cmd.Timeout {
		return errors.New("duration exceeds timeout")
	}

	if cmd.Duration > 0 && cmd.Timeout == cmd.Duration {
		cmd.Timeout = 0
	}

	if cmd.Timeout > 0 {
		var cancel func()
		ctx, cancel = context.WithTimeout(ctx, cmd.Timeout)
		defer cancel()
	}

	if cmd.Duration > 0 {
		var cancel context.CancelCauseFunc
		ctx, cancel = context.WithCancelCause(ctx)
		defer cancel(nil)

		time.AfterFunc(cmd.Duration, func() {
			cancel(errDuration)
		})
	}

	yc, err := cmd.NewClient(ctx, logger)
	if err != nil {
		return err
	}

	defer yc.Close()

	req := yat.Req{
		Path:  path,
		Data:  data,
		Limit: cmd.Limit,
	}

	enc := json.NewEncoder(os.Stdout)

	err = yc.Post(ctx, req, func(r yat.Res) error {
		if cmd.Raw {
			_, err := os.Stdout.Write(r.Data)
			return err
		}

		return enc.Encode(r)
	})

	if context.Cause(ctx) == errDuration {
		err = nil
	}

	return err
}
