package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"slices"
	"strings"

	"github.com/google/uuid"
	"yat.io/yat/cmd/yat/internal/flagset"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	logLevel := slog.LevelInfo

	flags := flagset.New()
	flags.Text(&logLevel, "log-level")

	args, err := flags.Parse(args)
	if err != nil {
		return err
	}

	// a subcommand is required
	if len(args) == 0 || args[0][0] == '-' {
		panic("usage")
	}

	ctx, _ = signal.NotifyContext(ctx, os.Interrupt)

	name, args := args[0], args[1:]

	var cmd interface {
		Run(ctx context.Context, logger *slog.Logger, args []string) error
	}

	// shared config
	clientCmd := &ClientCmd{
		Addr:   os.Getenv("YAT_ADDR"),
		TLSDir: os.Getenv("YAT_TLS_DIR"),
	}

	if clientCmd.Addr == "" {
		clientCmd.Addr = "localhost:25120"
	}

	switch name {
	case "publish", "pub":
		cmd = &PublishCmd{
			ClientCmd: clientCmd,
			File:      "/dev/stdin",
		}

	case "seed":
		cmd = &SeedCmd{}

	case "serve", "server":
		cmd = &ServeCmd{
			BindAddr: "localhost:25120",
		}

	case "subscribe", "sub":
		cmd = &SubscribeCmd{
			ClientCmd: clientCmd,
			Format:    "raw",
		}

	default:
		panic("unknown command")
	}

	// if the command has its own flags, merge them in
	if cmd, ok := cmd.(interface{ AddFlags(*flagset.Set) }); ok {
		cmd.AddFlags(flags)
	}

	for {
		fi := slices.IndexFunc(args, func(arg string) bool {
			return strings.HasPrefix(arg, "-")
		})

		if fi == -1 {
			break
		}

		// keep parsing combined flags
		tail, err := flags.Parse(args[fi:])
		if err != nil {
			return err
		}

		// preserve positional args
		args = append(args[:fi], tail...)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			switch a.Value.Kind() {
			case slog.KindDuration:
				return slog.Float64(a.Key, a.Value.Duration().Seconds())

			default:
				return a
			}
		},
	}))

	logger = logger.With("this", uuid.New())
	return cmd.Run(ctx, logger, args)
}
