package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"time"

	"yat.io/yat"
	"yat.io/yat/cmd/yat/internal/flagset"
)

type RequestCmd struct {
	*ClientConfig
	File    string
	Empty   bool
	Inbox   string
	Timeout time.Duration
	Raw     bool
}

func (cmd *RequestCmd) AddFlags(flags *flagset.Set) {
	flags.String(&cmd.File, "file", "f")
	flags.Bool(&cmd.Empty, "empty", "e")
	flags.String(&cmd.Inbox, "inbox", "i")
	flags.Duration(&cmd.Timeout, "timeout", "t")
	flags.Bool(&cmd.Raw, "raw")
}

func (cmd *RequestCmd) Run(ctx context.Context, logger *slog.Logger, args []string) error {
	if len(args) != 1 {
		return usageError{
			Usage: "yat request PATH",
			Topic: "request",
		}
	}

	msg, err := readMsg(args[0], cmd.Inbox, cmd.File, cmd.Empty)
	if err != nil {
		return err
	}

	if cmd.Timeout > 0 {
		var cancel func()
		ctx, cancel = context.WithTimeout(ctx, cmd.Timeout)
		defer cancel()
	}

	yc, err := cmd.NewClient(ctx, logger)
	if err != nil {
		return err
	}

	defer yc.Close()

	return yc.Request(ctx, msg, func(_ context.Context, m yat.Msg) error {
		if cmd.Raw {
			_, err := os.Stdout.Write(m.Data)
			return err
		}

		return json.NewEncoder(os.Stdout).Encode(m)
	})
}
