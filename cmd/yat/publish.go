package main

import (
	"context"
	"log/slog"

	"yat.io/yat/cmd/yat/internal/flagset"
)

type PublishCmd struct {
	*ClientConfig
	File  string
	Empty bool
	Inbox string
}

func (cmd *PublishCmd) AddFlags(flags *flagset.Set) {
	flags.String(&cmd.File, "file", "f")
	flags.Bool(&cmd.Empty, "empty", "e")
	flags.String(&cmd.Inbox, "inbox", "i")
}

func (cmd *PublishCmd) Run(ctx context.Context, logger *slog.Logger, args []string) error {
	if len(args) != 1 {
		return usageError{
			Usage: "yat publish PATH",
			Topic: "publish",
		}
	}

	msg, err := readMsg(args[0], cmd.Inbox, cmd.File, cmd.Empty)
	if err != nil {
		return err
	}

	yc, err := cmd.NewClient(ctx, logger)
	if err != nil {
		return err
	}

	defer yc.Close()

	return yc.Publish(ctx, msg)
}
