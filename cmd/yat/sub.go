package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"yat.io/yat"
	"yat.io/yat/cmd/yat/flagset"
	"yat.io/yat/topic"
)

type subCmd struct {
	Group string
	Limit int
}

func (cmd subCmd) Run(ctx context.Context, logger *slog.Logger, cfg sharedConfig, args []string) error {
	if len(args) != 1 {
		return errors.New("subscribe requires exactly one topic")
	}

	top, _, err := topic.Parse(args[0])
	if err != nil {
		return err
	}

	sel := yat.Sel{
		Topic: top,
		Limit: cmd.Limit,
		Group: yat.Group(cmd.Group),
	}

	client, err := cfg.NewClient(logger)
	if err != nil {
		return err
	}

	defer client.Close()

	sub, err := client.Subscribe(sel, func(m yat.Msg) {
		data, _ := json.Marshal(m)
		fmt.Println(string(data))
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

func (cmd *subCmd) SetupFlags(fs *flagset.Set) {
	fs.String(&cmd.Group, "group", "g")
	fs.Int(&cmd.Limit, "limit", "n")
}
