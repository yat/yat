package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/google/uuid"
	"yat.io/yat"
	"yat.io/yat/internal/flagset"
)

type ServeCmd struct {
	Bind string
}

func (cmd ServeCmd) Run(ctx context.Context, logger *slog.Logger, cfg SharedConfig, args []string) error {
	if len(args) != 0 {
		return usageError{
			Usage: "yat serve [flags]",
			Topic: "serve",
		}
	}

	if len(cmd.Bind) == 0 {
		cmd.Bind = cfg.Address
	}

	if err := cmd.run(ctx, logger); err != nil {
		return fmt.Errorf("yat serve: %v", err)
	}

	return nil
}

func (cmd ServeCmd) run(ctx context.Context, logger *slog.Logger) error {
	l, err := net.Listen("tcp", cmd.Bind)
	if err != nil {
		return err
	}

	defer l.Close()

	rr := yat.NewRouter()

	logger.InfoContext(ctx, "serve",
		"address", l.Addr().String())

	for {
		conn, err := l.Accept()
		if err != nil {
			break
		}

		go func() {
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			logger := logger.With(
				"conn", uuid.New().String(),
				"remote", conn.RemoteAddr().String(),
				"local", conn.LocalAddr().String())

			start := time.Now()
			logger.DebugContext(ctx, "connection opened")

			defer func() {
				logger.DebugContext(ctx, "connection closed",
					"elapsed", time.Since(start).Seconds())
			}()

			err := yat.Serve(ctx, conn, rr)
			if err == io.EOF {
				err = nil
			}

			if err != nil {
				logger.ErrorContext(ctx, "connection error", "error", err)
			}
		}()
	}

	return nil
}

func (cmd *ServeCmd) Flags() *flagset.Set {
	flags := flagset.New()
	flags.String(&cmd.Bind, "bind")
	return flags
}
