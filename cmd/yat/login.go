package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mattn/go-isatty"
	"github.com/pkg/browser"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
	"yat.io/yat/cmd"
	yatv1 "yat.io/yat/internal/wire/yat/v1"
)

type LoginCmd struct {
	*cmd.Config
}

func (cmd *LoginCmd) Run(ctx context.Context, logger *slog.Logger, args []string) error {
	if len(args) > 1 {
		return usageError{
			Usage: "yat login [SERVER]",
			Topic: "login",
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

	tcfg, watch, err := cmd.TLSFiles.ClientConfig()
	if err != nil {
		return err
	}

	go watch(ctx, logger)

	conn, err := grpc.NewClient(cmd.Server,
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
		grpc.WithTransportCredentials(credentials.NewTLS(tcfg)))
	if err != nil {
		return err
	}
	defer conn.Close()

	client := yatv1.NewLoginServiceClient(conn)
	stream, err := client.Login(ctx, &yatv1.LoginRequest{})
	if err != nil {
		return err
	}

	for {
		res, err := stream.Recv()
		if err == io.EOF {
			return errors.New("login ended before credentials")
		}
		if err != nil {
			return err
		}

		switch event := res.GetEvent().(type) {
		case *yatv1.LoginResponse_Start:
			url := event.Start.GetUrl()
			fmt.Fprintf(os.Stderr, "opening %s\n", url)
			if isatty.IsTerminal(os.Stderr.Fd()) {
				if err := browser.OpenURL(url); err != nil {
					fmt.Fprintf(os.Stderr, "error opening browser: %v\n", err)
				}
			}

		case *yatv1.LoginResponse_Creds:
			return writeLoginCreds(path, event.Creds)

		case *yatv1.LoginResponse_Error:
			msg := event.Error.GetMessage()
			if msg == "" {
				msg = "login failed"
			}
			return errors.New(msg)

		default:
			return errors.New("empty login response")
		}
	}
}

type loginCreds struct {
	mu     sync.Mutex
	Client yatv1.LoginServiceClient
	Path   string // to a credentials file written by `yat login`
}

func (lc *loginCreds) GetCreds(ctx context.Context, requestURI ...string) (map[string]string, error) {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	creds, err := readLoginCreds(lc.Path)
	if err != nil {
		return nil, err
	}

	token := strings.TrimSpace(creds.GetToken())
	deadline := time.Now().Add(30 * time.Second)
	expiry := creds.GetExpiry()

	if token != "" && expiry != nil && expiry.IsValid() && expiry.AsTime().After(deadline) {
		return map[string]string{
			"authorization": "Bearer " + token,
		}, nil
	}

	res, err := lc.Client.RefreshLogin(ctx, &yatv1.RefreshLoginRequest{
		Refresh: new(strings.TrimSpace(creds.GetRefresh())),
	})

	if err != nil {
		return nil, err
	}

	creds = res.GetCreds()
	if creds == nil {
		return nil, errors.New("missing login credentials")
	}

	token = strings.TrimSpace(creds.GetToken())
	if token == "" {
		return nil, errors.New("missing login token")
	}

	if err := writeLoginCreds(lc.Path, creds); err != nil {
		return nil, err
	}

	return map[string]string{
		"authorization": "Bearer " + token,
	}, nil
}

func loginCredsFile(configDir string, server string) (string, error) {
	if server == "." || server == ".." || strings.ContainsAny(server, `/\`) {
		return "", fmt.Errorf("server %q cannot be used as a login file name", server)
	}

	return filepath.Join(configDir, "login", server), nil
}

func writeLoginCreds(path string, creds *yatv1.LoginCreds) error {
	if creds == nil {
		return errors.New("missing login credentials")
	}

	data, err := proto.Marshal(creds)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	return os.WriteFile(path, data, 0o600)
}

func readLoginCreds(path string) (*yatv1.LoginCreds, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var creds yatv1.LoginCreds
	if err := proto.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("parse %s: %v", path, err)
	}

	return &creds, nil
}
