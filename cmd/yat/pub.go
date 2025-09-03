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

type pubCmd struct {
	Inbox string
	Data  string
	File  string
	Empty bool
	Count int
}

func (cmd pubCmd) Run(ctx context.Context, logger *slog.Logger, cfg sharedConfig, args []string) error {
	if len(args) != 1 {
		return errors.New("publish requires exactly one topic")
	}

	top, _, err := topic.Parse(args[0])
	if err != nil {
		return err
	}

	m := yat.Msg{
		Topic: top,
	}

	if len(cmd.Inbox) > 0 {
		in, _, err := topic.Parse(cmd.Inbox)
		if err != nil {
			return fmt.Errorf("inbox: %v", err)
		}
		m.Inbox = in
	}

	switch {
	case cmd.Empty:
		break

	case len(cmd.Data) > 0:
		m.Data = []byte(cmd.Data)

	case len(cmd.File) > 0:
		data, err := os.ReadFile(cmd.File)
		if err != nil {
			return err
		}
		m.Data = data
	}

	client := cfg.NewClient(logger)
	defer client.Close()

	for range max(1, cmd.Count) {
		if err := client.Publish(m); err != nil {
			return err
		}
	}

	return client.Flush(ctx)
}

func (cmd *pubCmd) SetupFlags(fs *flagset.Set) {
	fs.String(&cmd.Inbox, "inbox", "i")
	fs.Bool(&cmd.Empty, "empty", "e")
	fs.String(&cmd.Data, "data", "d")
	fs.String(&cmd.File, "file", "f")
	fs.Int(&cmd.Count, "count", "n")
}
