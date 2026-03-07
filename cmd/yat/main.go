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

	_ "golang.org/x/crypto/x509roots/fallback"
)

type usageError struct {
	Usage string
	Topic string
}

var errNoCommand = usageError{
	Usage: "yat [flags] COMMAND [args]",
}

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	sharedConfig := &SharedConfig{
		LogLevel: slog.LevelInfo,
		TLSDir:   os.Getenv("YAT_TLS_DIR"),
	}

	if ll, ok := os.LookupEnv("YAT_LOG_LEVEL"); ok {
		if err := sharedConfig.LogLevel.UnmarshalText([]byte(ll)); err != nil {
			return err
		}
	}

	// embedded in client cmds
	clientConfig := &ClientConfig{
		SharedConfig: sharedConfig,
		Server:       os.Getenv("YAT_SERVER"),
	}

	if clientConfig.Server == "" {
		clientConfig.Server = "localhost:25120"
	}

	flags := flagset.New()
	flags.Text(&sharedConfig.LogLevel, "log-level")
	flags.String(&sharedConfig.TLSDir, "tls-dir")
	flags.String(&clientConfig.Server, "server")

	args, err := flags.Parse(args)
	if err != nil {
		return err
	}

	// a subcommand is required
	if len(args) == 0 || args[0][0] == '-' {
		return errNoCommand
	}

	ctx, _ = signal.NotifyContext(ctx, os.Interrupt)

	name, args := args[0], args[1:]

	var cmd interface {
		Run(ctx context.Context, logger *slog.Logger, args []string) error
	}

	switch name {
	case "help":
		cmd = &HelpCmd{}

	case "publish", "pub":
		cmd = &PublishCmd{
			ClientConfig: clientConfig,
			File:         "/dev/stdin",
		}

	case "subscribe", "sub":
		cmd = &SubscribeCmd{
			ClientConfig: clientConfig,
		}

	case "serve", "server":
		cmd = &ServeCmd{
			SharedConfig: sharedConfig,
			BindAddr:     "localhost:25120",
		}

	case "seed":
		cmd = &SeedCmd{}

	default:
		return fmt.Errorf("yat %s: unknown command", name)
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
		Level: sharedConfig.LogLevel,
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

func (ue usageError) Error() string {
	if ue == (usageError{}) {
		return "usage error"
	}

	help := "yat help"
	if len(ue.Topic) > 0 {
		help += " " + ue.Topic
	}

	return fmt.Sprintf("usage: %s\nRun '%s' for details.", ue.Usage, help)
}
