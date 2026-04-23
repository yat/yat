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
	"yat.io/yat/cmd"
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
	cfg := cmd.EnvConfig()
	flags := flagset.New()

	// shared flags
	flags.Text(&cfg.LogLevel, "log-level")
	flags.String(&cfg.TLSFiles.CertFile, "tls-cert-file")
	flags.String(&cfg.TLSFiles.KeyFile, "tls-key-file")
	flags.Strings(&cfg.TLSFiles.CAFiles, "tls-ca-file")

	// client flags
	flags.String(&cfg.Server, "server")
	flags.String(&cfg.TokenFile, "token-file")

	args, err := flags.Parse(args)
	if err != nil {
		return err
	}

	if flags.Help {
		return HelpCmd{}.Run(ctx, nil, nil)
	}

	// a subcommand is required
	if len(args) == 0 || args[0][0] == '-' {
		return errNoCommand
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()

	name, args := args[0], args[1:]

	var cmd interface {
		Run(ctx context.Context, logger *slog.Logger, args []string) error
	}

	switch name {
	case "handle", "respond", "res":
		cmd = &HandleCmd{
			Config: &cfg,
			File:   "/dev/stdin",
		}

	case "help":
		cmd = &HelpCmd{}

	case "post", "request", "req":
		cmd = &PostCmd{
			Config: &cfg,
			File:   "/dev/stdin",
			Limit:  1,
		}

	case "publish", "pub":
		cmd = &PublishCmd{
			Config: &cfg,
			File:   "/dev/stdin",
		}

	case "seed":
		cmd = &SeedCmd{}

	case "serve", "server":
		cmd = &ServeCmd{
			Config:   &cfg,
			BindAddr: "localhost:25120",
		}

	case "subscribe", "sub":
		cmd = &SubscribeCmd{
			Config: &cfg,
		}

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

	// flag shadows YAT_TOKEN
	if flags.Has("token-file") {
		cfg.Token = ""
	}

	if flags.Help && name != "help" {
		args = []string{name}
		cmd = HelpCmd{}
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: cfg.LogLevel,
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
