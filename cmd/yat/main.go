package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"slices"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"yat.io/yat"
	"yat.io/yat/cmd"
	"yat.io/yat/cmd/yat/internal/flagset"

	_ "golang.org/x/crypto/x509roots/fallback"
	yatv1 "yat.io/yat/internal/wire/yat/v1"
)

type clientCmd struct {
	*cmd.Config
}

type usageError struct {
	Usage string
	Topic string
}

var errNoCommand = usageError{
	Usage: "yat [flags] COMMAND [args]",
}

var (
	errNegDuration = errors.New("negative duration")
	errNegLimit    = errors.New("negative limit")
	errNegTimeout  = errors.New("negative timeout")
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	logLevel := slog.LevelInfo
	if ll, ok := os.LookupEnv("YAT_LOG_LEVEL"); ok {
		_ = logLevel.UnmarshalText([]byte(ll))
	}

	cfg := cmd.EnvConfig()
	flags := flagset.New()

	// shared flags
	flags.Text(&logLevel, "log-level")
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
			clientCmd: clientCmd{&cfg},
			File:      "/dev/stdin",
		}

	case "help":
		cmd = &HelpCmd{}

	case "login":
		cmd = &LoginCmd{
			Config: &cfg,
		}

	case "logout":
		cmd = &LogoutCmd{
			Config: &cfg,
		}

	case "post", "request", "req":
		cmd = &PostCmd{
			clientCmd:  clientCmd{&cfg},
			File:       "/dev/stdin",
			Limit:      1,
			DataFormat: dfString,
		}

	case "publish", "pub":
		cmd = &PublishCmd{
			clientCmd: clientCmd{&cfg},
			File:      "/dev/stdin",
		}

	case "serve", "server":
		cmd = &ServeCmd{
			Config:      &cfg,
			BindAddr:    "localhost:25120",
			RequireCert: true,
		}

	case "subscribe", "sub":
		cmd = &SubscribeCmd{
			clientCmd:  clientCmd{&cfg},
			DataFormat: dfString,
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

	return cmd.Run(ctx, logger, args)
}

// newClient is like [cmd.Config.NewClient], but adds support for login credentials.
func (cc clientCmd) newClient(ctx context.Context, logger *slog.Logger) (*yat.Client, error) {
	if cc.Server == "" {
		return nil, errors.New("server is not configured")
	}

	tcfg, watch, err := cc.TLSFiles.ClientConfig()
	if err != nil {
		return nil, err
	}

	go watch(ctx, logger)

	cfg := yat.ClientConfig{
		Logger:    logger,
		TLSConfig: tcfg,
	}

	switch {
	case cc.Token != "":
		token := strings.TrimSpace(cc.Token)
		cfg.GetCreds = yat.BearerToken(token)

	case cc.TokenFile != "":
		cfg.GetCreds = yat.TokenFile(cc.TokenFile)

	default:
		credsFile, err := loginCredsFile(cc.ConfigDir, cc.Server)
		if err != nil {
			return nil, err
		}

		if _, err := os.Stat(credsFile); err == nil {
			cc, err := grpc.NewClient(cc.Server,
				grpc.WithTransportCredentials(credentials.NewTLS(tcfg)))

			if err != nil {
				return nil, err
			}

			go func() {
				<-ctx.Done()
				cc.Close()
			}()

			lc := &loginCreds{
				Client: yatv1.NewLoginServiceClient(cc),
				Path:   credsFile,
			}

			cfg.GetCreds = lc.GetCreds
		}
	}

	return yat.NewClient(cc.Server, cfg)
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
