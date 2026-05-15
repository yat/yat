package main

import (
	"context"
	"errors"
	"log/slog"
	"os"

	"yat.io/yat/cmd"
)

type LogoutCmd struct {
	*cmd.Config
}

func (cmd *LogoutCmd) Run(_ context.Context, _ *slog.Logger, args []string) error {
	if len(args) > 1 {
		return usageError{
			Usage: "yat logout [SERVER]",
			Topic: "logout",
		}
	}

	if len(args) == 1 {
		cmd.Server = args[0]
	}

	if cmd.Server == "" {
		return errors.New("server is not configured")
	}

	path, err := loginCredsFile(cmd.ConfigDir, cmd.Server)
	if err != nil {
		return err
	}

	if err := os.Remove(path); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}

	return nil
}
