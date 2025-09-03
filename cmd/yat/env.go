package main

import (
	"context"
	"fmt"
	"log/slog"
)

type envCmd struct{}

func (cmd envCmd) Run(ctx context.Context, logger *slog.Logger, cfg sharedConfig, args []string) error {
	fmt.Printf("YAT_LOG_LEVEL=%v\n", cfg.LogLevel)

	if len(cfg.Server) != 0 {
		fmt.Printf("YAT_SERVER=%v\n", cfg.Server)
	}

	return nil
}
