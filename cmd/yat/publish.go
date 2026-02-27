package main

import (
	"context"
	"errors"
	"log/slog"
	"os"

	"yat.io/yat"
	"yat.io/yat/cmd/yat/internal/flagset"
)

type PublishCmd struct {
	Config *ClientConfig
	Empty  bool
	File   string
	Inbox  string
}

func (cmd *PublishCmd) AddFlags(flags *flagset.Set) {
	flags.Bool(&cmd.Empty, "empty", "e")
	flags.String(&cmd.File, "file", "f")
	flags.String(&cmd.Inbox, "inbox", "i")
}

func (cmd *PublishCmd) Run(ctx context.Context, logger *slog.Logger, args []string) error {
	if len(args) != 1 {
		return errors.New("publish takes exactly 1 argument (a path)")
	}

	path, _, err := yat.ParsePath(args[0])
	if err != nil {
		return err
	}

	var inbox yat.Path
	if cmd.Inbox != "" {
		inbox, _, err = yat.ParsePath(cmd.Inbox)
		if err != nil {
			return err
		}
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

	yc, err := cmd.Config.NewClient(ctx, logger)
	if err != nil {
		return err
	}

	defer yc.Close()

	return yc.Publish(yat.Msg{
		Path:  path,
		Data:  data,
		Inbox: inbox,
	})
}
