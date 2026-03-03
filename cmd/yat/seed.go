package main

import (
	"context"
	"log/slog"
	"net"
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
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	var (
		tlsCertFile = filepath.Join(dir, "tls.crt")
		tlsKeyFile  = filepath.Join(dir, "tls.key")
		tlsCAFile   = filepath.Join(dir, "ca.crt")
		tlsFiles    = []string{tlsCertFile, tlsKeyFile, tlsCAFile}
	)

	for _, name := range tlsFiles {
		if err := os.RemoveAll(name); err != nil {
			return err
		}
	}

	caCrt, caKey, err := pkigen.NewRoot(
		pkigen.URI("spiffe://yat"),
	)
	if err != nil {
		return err
	}

	tlsCrt, tlsKey, err := pkigen.NewLeaf(caCrt, caKey,
		pkigen.CN("yat-dev"),
		pkigen.DNS("localhost"),
		pkigen.IP(net.IPv4(127, 0, 0, 1)),
		pkigen.IP(net.IPv6loopback),
		pkigen.URI("spiffe://yat/dev"),
	)
	if err != nil {
		return err
	}

	tlsKeyPEM, err := pkigen.EncodePrivateKey(tlsKey)
	if err != nil {
		return err
	}

	if err := os.WriteFile(tlsCertFile, pkigen.EncodeCerts(tlsCrt), 0o600); err != nil {
		return err
	}

	if err := os.WriteFile(tlsKeyFile, tlsKeyPEM, 0o600); err != nil {
		return err
	}

	if err := os.WriteFile(tlsCAFile, pkigen.EncodeCerts(caCrt), 0o600); err != nil {
		return err
	}

	return nil
}
