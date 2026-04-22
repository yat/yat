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
		LogLevel:    slog.LevelInfo,
		TLSCertFile: os.Getenv("YAT_TLS_CERT_FILE"),
		TLSKeyFile:  os.Getenv("YAT_TLS_KEY_FILE"),
	}

	if ll, ok := os.LookupEnv("YAT_LOG_LEVEL"); ok {
		if err := sharedConfig.LogLevel.UnmarshalText([]byte(ll)); err != nil {
			return err
		}
	}

	if name, ok := os.LookupEnv("YAT_TLS_CA_FILE"); ok {
		if name := strings.TrimSpace(name); name != "" {
			sharedConfig.TLSCAFiles = append(sharedConfig.TLSCAFiles, name)
		}
	}

	if names, ok := os.LookupEnv("YAT_TLS_CA_FILES"); ok {
		for name := range strings.SplitSeq(names, ",") {
			if name := strings.TrimSpace(name); name != "" {
				sharedConfig.TLSCAFiles = append(sharedConfig.TLSCAFiles, name)
			}
		}
	}

	// embedded in client cmds
	clientConfig := &ClientConfig{
		SharedConfig: sharedConfig,
		Server:       os.Getenv("YAT_SERVER"),
		StaticToken:  os.Getenv("YAT_TOKEN"),
		TokenFile:    os.Getenv("YAT_TOKEN_FILE"),
	}

	flags := flagset.New()

	// shared flags
	flags.Text(&sharedConfig.LogLevel, "log-level")
	flags.String(&sharedConfig.TLSCertFile, "tls-cert-file")
	flags.String(&sharedConfig.TLSKeyFile, "tls-key-file")
	flags.Strings(&sharedConfig.TLSCAFiles, "tls-ca-file")

	// client flags
	flags.String(&clientConfig.Server, "server")
	flags.String(&clientConfig.TokenFile, "token-file")

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
			ClientConfig: clientConfig,
			File:         "/dev/stdin",
		}

	case "help":
		cmd = &HelpCmd{}

	case "post", "request", "req":
		cmd = &PostCmd{
			ClientConfig: clientConfig,
			File:         "/dev/stdin",
			Limit:        1,
		}

	case "publish", "pub":
		cmd = &PublishCmd{
			ClientConfig: clientConfig,
			File:         "/dev/stdin",
		}

	case "seed":
		cmd = &SeedCmd{}

	case "serve", "server":
		cmd = &ServeCmd{
			SharedConfig: sharedConfig,
			BindAddr:     "localhost:25120",
		}

	case "subscribe", "sub":
		cmd = &SubscribeCmd{
			ClientConfig: clientConfig,
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

	if flags.Help && name != "help" {
		args = []string{name}
		cmd = HelpCmd{}
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
