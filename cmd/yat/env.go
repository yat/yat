package main

import (
	"context"
	"fmt"
	"log/slog"
)

type envCmd struct{}

func (cmd envCmd) Run(ctx context.Context, logger *slog.Logger, cfg sharedConfig, args []string) error {
	fmt.Printf("YAT_ADDRESS=%v\n", cfg.Address)
	fmt.Printf("YAT_LOG_LEVEL=%v\n", cfg.LogLevel)

	if len(cfg.TLSCAFile) > 0 {
		fmt.Printf("YAT_TLS_CA_FILE=%v\n", cfg.TLSCAFile)
	}

	if len(cfg.TLSCertFile) > 0 {
		fmt.Printf("YAT_TLS_CERT_FILE=%v\n", cfg.TLSCertFile)
	}

	if len(cfg.TLSKeyFile) > 0 {
		fmt.Printf("YAT_TLS_KEY_FILE=%v\n", cfg.TLSKeyFile)
	}

	return nil
}
