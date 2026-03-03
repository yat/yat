package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"

	"yat.io/yat/cmd/yat/internal/pkigen"
)

type SeedCmd struct{}

func (cmd *SeedCmd) Run(ctx context.Context, logger *slog.Logger, args []string) error {
	if len(args) != 1 {
		return usageError{
			Usage: "yat seed DIR",
			Topic: "seed",
		}
	}

	dir := args[0]
	tlsDir := filepath.Join(dir, "tls")
	if err := os.MkdirAll(tlsDir, 0o700); err != nil {
		return err
	}

	var (
		tlsServerCertFile = filepath.Join(tlsDir, "server.crt")
		tlsServerKeyFile  = filepath.Join(tlsDir, "server.key")
		tlsClientCertFile = filepath.Join(tlsDir, "client.crt")
		tlsClientKeyFile  = filepath.Join(tlsDir, "client.key")
		tlsCAFile         = filepath.Join(tlsDir, "ca.crt")

		tlsFiles = []string{
			tlsServerCertFile,
			tlsServerKeyFile,
			tlsClientCertFile,
			tlsClientKeyFile,
			tlsCAFile,
		}
	)

	for _, name := range tlsFiles {
		if err := os.RemoveAll(name); err != nil {
			return err
		}
	}

	caCrt, caKey, err := pkigen.NewRoot()
	if err != nil {
		return err
	}

	serverCrt, serverKey, err := pkigen.NewLeaf(caCrt, caKey,
		pkigen.CN("yat-server"), pkigen.DNS("localhost"))

	if err != nil {
		return err
	}

	clientCrt, clientKey, err := pkigen.NewLeaf(caCrt, caKey,
		pkigen.CN("yat-client"))

	if err != nil {
		return err
	}

	serverKeyPEM, err := pkigen.EncodePrivateKey(serverKey)
	if err != nil {
		return err
	}

	clientKeyPEM, err := pkigen.EncodePrivateKey(clientKey)
	if err != nil {
		return err
	}

	if err := os.WriteFile(tlsServerCertFile, pkigen.EncodeCerts(serverCrt), 0o600); err != nil {
		return err
	}

	if err := os.WriteFile(tlsServerKeyFile, serverKeyPEM, 0o600); err != nil {
		return err
	}

	if err := os.WriteFile(tlsClientCertFile, pkigen.EncodeCerts(clientCrt), 0o600); err != nil {
		return err
	}

	if err := os.WriteFile(tlsClientKeyFile, clientKeyPEM, 0o600); err != nil {
		return err
	}

	if err := os.WriteFile(tlsCAFile, pkigen.EncodeCerts(caCrt), 0o600); err != nil {
		return err
	}

	return nil
}
