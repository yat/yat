// Yat is the command-line client and server.
// For a list of commands, build this package and run yat help.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"
	"time"

	"yat.io/yat/internal/flagset"
)

type SharedConfig struct {
	Address  string
	LogLevel slog.Level

	// client flags

	TLSCertFile string
	TLSKeyFile  string
	TLSCAFile   string
}

type usageError struct {
	Usage string
	Topic string
}

var errUsage = usageError{
	Usage: "yat [flags] command [args]",
}

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	cfg := SharedConfig{
		Address:     getDefaultAddress(),
		LogLevel:    getDefaultLogLevel(),
		TLSCertFile: os.Getenv("YAT_TLS_CERT_FILE"),
		TLSKeyFile:  os.Getenv("YAT_TLS_KEY_FILE"),
		TLSCAFile:   os.Getenv("YAT_TLS_CA_FILE"),
	}

	flags := flagset.New()
	flags.String(&cfg.Address, "addr")
	flags.Text(&cfg.LogLevel, "log-level")
	flags.String(&cfg.TLSCertFile, "tls-cert-file")
	flags.String(&cfg.TLSKeyFile, "tls-key-file")
	flags.String(&cfg.TLSCAFile, "tls-ca-file")

	args, err := flags.Parse(args)
	if err != nil {
		return err
	}

	if len(args) == 0 || args[0][0] == '-' {
		return errUsage
	}

	name, args := args[0], args[1:]

	var cmd interface {
		Run(ctx context.Context, logger *slog.Logger, cfg SharedConfig, args []string) error
	}

	switch name {
	case "publish", "pub":
		cmd = &PublishCmd{}

	case "subscribe", "sub":
		cmd = &SubscribeCmd{}

	case "request", "req":
		cmd = &RequestCmd{}

	case "respond", "res":
		cmd = &RespondCmd{}

	case "serve":
		cmd = &ServeCmd{}

	case "help":
		cmd = &HelpCmd{}

	case "version":
		cmd = &VersionCmd{}

	default:
		return fmt.Errorf("yat %s: unknown command", name)
	}

	// now we know which command to run
	// but args may contain shared flags,
	// command flags, and command args

	// if the command has its own flags, merge them in
	if cmd, ok := cmd.(interface{ Flags() *flagset.Set }); ok {
		flags = flagset.Merge(flags, cmd.Flags())
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

	// all flags are parsed,
	// set up the logger

	lopt := slog.HandlerOptions{
		Level: cfg.LogLevel,
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &lopt))
	logger.DebugContext(ctx, "run", "command", name)

	start := time.Now()
	defer func() {
		logger.DebugContext(ctx, "stop",
			"command", name,
			"elapsed", time.Since(start).Seconds(),
		)
	}()

	// run the command at last
	return cmd.Run(ctx, logger, cfg, args)
}

// Dial connects to the server.
func (cfg SharedConfig) Dial(ctx context.Context) (net.Conn, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	if len(cfg.TLSCertFile) > 0 && len(cfg.TLSKeyFile) > 0 {
		crt, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return nil, err
		}

		tlsConfig.Certificates = []tls.Certificate{crt}
	}

	if len(cfg.TLSCAFile) > 0 {
		tlsConfig.RootCAs = x509.NewCertPool()
		rootCerts, err := os.ReadFile(cfg.TLSCAFile)
		if err != nil {
			return nil, err
		}

		if !tlsConfig.RootCAs.AppendCertsFromPEM(rootCerts) {
			return nil, fmt.Errorf("read %s: no certificates", cfg.TLSCAFile)
		}
	}

	d := &tls.Dialer{
		Config: tlsConfig,
	}

	return d.DialContext(ctx, "tcp", cfg.Address)
}

// getDefaultLogLevel returns the result of parsing YAT_LOG_LEVEL or [slog.LevelError].
func getDefaultLogLevel() slog.Level {
	lvl := slog.LevelError
	if s, ok := os.LookupEnv("YAT_LOG_LEVEL"); ok {
		lvl.UnmarshalText([]byte(s))
	}

	return lvl
}

// getDefaultAddress returns YAT_ADDR or "localhost:63197".
func getDefaultAddress() string {
	if addr, ok := os.LookupEnv("YAT_ADDR"); ok {
		return addr
	}
	return "localhost:63197"
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
