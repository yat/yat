package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"yat.io/yat"
	"yat.io/yat/cmd/yat/flagset"
	"yat.io/yat/topic"
)

type respondCmd struct {
	Limit int
	Group string

	// response

	Inbox string
	Data  string
	File  string
	Empty bool

	// FIX: -format?
	// FIX: -exec?
}

func (cmd respondCmd) Run(ctx context.Context, logger *slog.Logger, cfg sharedConfig, args []string) error {
	if len(args) != 1 {
		return errors.New("respond requires exactly one topic")
	}

	top, _, err := topic.Parse(args[0])
	if err != nil {
		return err
	}

	var oinbox topic.Path

	if len(cmd.Inbox) > 0 {
		in, _, err := topic.Parse(cmd.Inbox)
		if err != nil {
			return fmt.Errorf("inbox: %v", err)
		}
		oinbox = in
	}

	var odata []byte

	switch {
	case cmd.Empty:
		break

	case len(cmd.Data) > 0:
		odata = []byte(cmd.Data)

	case len(cmd.File) > 0:
		data, err := os.ReadFile(cmd.File)
		if err != nil {
			return err
		}
		odata = data
	}

	client, err := cfg.NewClient(logger)
	if err != nil {
		return err
	}

	defer client.Close()

	sel := yat.Sel{
		Topic: top,
	}

	if cmd.Limit > 0 {
		sel.Limit = cmd.Limit
	}

	if len(cmd.Group) > 0 {
		sel.Group = yat.Group(cmd.Group)
	}

	sub, err := client.Subscribe(sel, yat.SubFlagResponder, func(in yat.Msg) {
		out := yat.Msg{
			Topic: in.Inbox,
			Inbox: oinbox,
			Data:  odata,
		}

		logger.Log(ctx, slog.LevelDebug-1, "responding", "in", in, "out", out)
		if err := client.Publish(out); err != nil {
			panic(err)
		}
	})

	if err != nil {
		return err
	}

	defer sub.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()

	case <-sub.Stopped():
		return nil
	}
}

func (cmd *respondCmd) SetupFlags(fs *flagset.Set) {
	fs.String(&cmd.Group, "group", "g")
	fs.Int(&cmd.Limit, "limit", "n")

	fs.String(&cmd.Inbox, "inbox", "i")
	fs.Bool(&cmd.Empty, "empty", "e")
	fs.String(&cmd.Data, "data", "d")
	fs.String(&cmd.File, "file", "f")
}
