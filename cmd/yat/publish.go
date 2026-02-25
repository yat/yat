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
	*ClientCmd
	Empty bool
	File  string
	Inbox string
}

func (cmd *PublishCmd) AddFlags(flags *flagset.Set) {
	cmd.ClientCmd.AddFlags(flags)
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

	yc, err := cmd.newClient(ctx, logger)
	if err != nil {
		return err
	}

	defer yc.Close()

	err = yc.Publish(yat.Msg{
		Path:  path,
		Data:  data,
		Inbox: inbox,
	})

	if err != nil {
		yc.Close()
		return err
	}

	return nil
}
