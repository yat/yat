package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"yat.io/yat"
	"yat.io/yat/cmd/yat/flagset"
	"yat.io/yat/topic"
)

type callCmd struct {
	Inbox string
	Data  string
	File  string
	Empty bool

	Timeout time.Duration
}

func (cmd callCmd) Run(ctx context.Context, logger *slog.Logger, cfg sharedConfig, args []string) error {
	if len(args) != 1 {
		return errors.New("call requires exactly one topic")
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

	client, err := cfg.NewClient(logger)
	if err != nil {
		return err
	}

	defer client.Close()

	if cmd.Timeout > 0 {
		var cancel func()
		ctx, cancel = context.WithTimeout(ctx, cmd.Timeout)
		defer cancel()

		m.Deadline = time.Now().Add(cmd.Timeout)
	}

	err = client.Call(ctx, m, func(out yat.Msg) error {
		_, err := printmln(out)
		return err
	})

	if err != nil {
		return fmt.Errorf("call %s: %v", m.Topic, err)
	}

	return nil
}

func (cmd *callCmd) SetupFlags(fs *flagset.Set) {
	fs.String(&cmd.Inbox, "inbox", "i")
	fs.Bool(&cmd.Empty, "empty", "e")
	fs.String(&cmd.Data, "data", "d")
	fs.String(&cmd.File, "file", "f")
	fs.Duration(&cmd.Timeout, "timeout", "t")
}
