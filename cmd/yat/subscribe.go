package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"strings"

	"yat.io/yat"
	"yat.io/yat/cmd/yat/internal/flagset"
)

type SubscribeCmd struct {
	Config *ClientConfig
	Format string
}

func (cmd *SubscribeCmd) AddFlags(flags *flagset.Set) {
	flags.String(&cmd.Format, "format")
}

func (cmd *SubscribeCmd) Run(ctx context.Context, logger *slog.Logger, args []string) error {
	if len(args) == 0 {
		return errors.New("subscribe takes at least 1 pattern argument")
	}

	yc, err := cmd.Config.NewClient(ctx, logger)
	if err != nil {
		return err
	}

	defer yc.Close()

	callback := func(m yat.Msg) {
		var err error
		switch strings.ToLower(cmd.Format) {
		case "json", "jsonl":
			err = json.NewEncoder(os.Stdout).Encode(m)

		default:
			_, err = os.Stdout.Write(m.Data)
		}

		if err != nil {
			logger.ErrorContext(ctx, "write failed", "error", err)
		}
	}

	for _, arg := range args {
		path, _, err := yat.ParsePath(arg)
		if err != nil {
			return err
		}

		if _, err := yc.Subscribe(yat.Sel{Path: path}, callback); err != nil {
			return err
		}
	}

	<-ctx.Done()
	return nil
}
