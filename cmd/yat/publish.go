package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"yat.io/yat"
	"yat.io/yat/internal/flagset"
)

type PublishCmd struct {
	Path  string
	File  string
	Empty bool
	Reply string
}

func (cmd PublishCmd) Run(ctx context.Context, logger *slog.Logger, cfg SharedConfig, args []string) error {
	if len(args) != 1 {
		return usageError{
			Usage: "yat publish [flags] PATH",
			Topic: "publish",
		}
	}

	cmd.Path = args[0]
	if len(cmd.File) == 0 {
		cmd.File = "/dev/stdin"
	}

	if err := cmd.run(ctx, logger, cfg); err != nil {
		return fmt.Errorf("yat publish %s: %v", cmd.Path, err)
	}

	return nil
}

func (cmd PublishCmd) run(ctx context.Context, _ *slog.Logger, cfg SharedConfig) error {
	var data []byte
	var err error

	if !cmd.Empty {
		data, err = os.ReadFile(cmd.File)
		if err != nil {
			return err
		}
	}

	path, wild, err := yat.ParsePath([]byte(cmd.Path))
	if err != nil {
		return err
	}

	if wild {
		return errors.New("wildcard path")
	}

	var reply yat.Path
	if len(cmd.Reply) > 0 {
		reply, wild, err = yat.ParsePath([]byte(cmd.Reply))
		if err != nil {
			return errors.New("invalid reply path")
		}

		if wild {
			return errors.New("wildcard reply path")
		}
	}

	conn, err := cfg.Dial(ctx)
	if err != nil {
		return err
	}

	cc := yat.NewConn(conn)
	defer cc.Close()

	return cc.Publish(yat.Msg{
		Data:  data,
		Path:  path,
		Reply: reply,
	})
}

func (cmd *PublishCmd) Flags() *flagset.Set {
	flags := flagset.New()
	flags.String(&cmd.File, "file", "f")
	flags.Bool(&cmd.Empty, "empty", "e")
	flags.String(&cmd.Reply, "reply", "r")
	return flags
}
