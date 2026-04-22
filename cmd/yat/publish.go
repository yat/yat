package main

import (
	"context"
	"io"
	"log/slog"
	"os"

	"yat.io/yat"
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

func readMsg(path, inbox string, file string, empty bool) (m yat.Msg, err error) {
	m.Path, err = yat.ParsePath(path)
	if err != nil {
		return
	}

	if inbox != "" {
		if m.Inbox, err = yat.ParsePath(inbox); err != nil {
			return
		}
	}

	if !empty {
		if file == "-" || file == "/dev/stdin" {
			m.Data, err = io.ReadAll(os.Stdin)
		} else {
			m.Data, err = os.ReadFile(file)
		}
	}

	return
}
