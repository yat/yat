package main

import (
	"context"
	"io"
	"log/slog"
	"os"

	"yat.io/yat"
	"yat.io/yat/cmd"
	"yat.io/yat/cmd/yat/internal/flagset"
)

type PublishCmd struct {
	*cmd.Config

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

	path, err := yat.ParsePath(args[0])
	if err != nil {
		return err
	}

	data, err := loadData(cmd.File, cmd.Empty)
	if err != nil {
		return err
	}

	var inbox yat.Path
	if cmd.Inbox != "" {
		inbox, err = yat.ParsePath(cmd.Inbox)
		if err != nil {
			return err
		}
	}

	m := yat.Msg{
		Path:  path,
		Data:  data,
		Inbox: inbox,
	}

	yc, err := cmd.NewClient(ctx, logger)
	if err != nil {
		return err
	}

	defer yc.Close()

	return yc.Publish(ctx, m)
}

func loadData(file string, empty bool) (data []byte, err error) {
	switch {
	case empty:
		return

	case file == "-" || file == "/dev/stdin":
		return io.ReadAll(os.Stdin)

	default:
		return os.ReadFile(file)
	}
}
