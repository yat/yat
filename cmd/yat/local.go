package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"yat.io/yat/internal/pkigen"
)

type LocalCmd struct{}

//go:embed local
var localFS embed.FS

func (cmd LocalCmd) Run(ctx context.Context, logger *slog.Logger, cfg SharedConfig, args []string) error {
	if len(args) != 1 {
		return usageError{
			Usage: "yat local DIR",
			Topic: "local",
		}
	}

	dir := filepath.Clean(args[0])
	if info, err := os.Stat(dir); err == nil && !info.IsDir() {
		return fmt.Errorf("%s: not a directory", dir)
	}

	if matches, _ := filepath.Glob(filepath.Join(dir, "*")); len(matches) > 0 {
		return fmt.Errorf("%s: directory not empty", dir)
	}

	stubFS, err := fs.Sub(localFS, "local")
	if err != nil {
		return err
	}

	if err := os.CopyFS(dir, stubFS); err != nil {
		return err
	}

	var (
		tlsCACertFile     = filepath.Join(dir, "tls/ca.crt")
		tlsSvrCertFile    = filepath.Join(dir, "tls/server.crt")
		tlsSvrKeyFile     = filepath.Join(dir, "tls/server.key")
		tlsClientCertFile = filepath.Join(dir, "tls/client.crt")
		tlsClientKeyFile  = filepath.Join(dir, "tls/client.key")
	)

	if err := os.Mkdir(filepath.Join(dir, "tls"), 0o700); err != nil {
		return err
	}

	caCrt, caKey, err := pkigen.NewRoot()
	if err != nil {
		return err
	}

	svrCrt, svrKey, err := pkigen.NewLeaf(caCrt, caKey, pkigen.DNS("local-yat"))
	if err != nil {
		return err
	}

	clientCrt, clientKey, err := pkigen.NewLeaf(caCrt, caKey, pkigen.CN("yat client"))
	if err != nil {
		return err
	}

	if err := writeLocalCertFile(tlsCACertFile, caCrt); err != nil {
		return err
	}

	if err := writeLocalCertFile(tlsSvrCertFile, svrCrt); err != nil {
		return err
	}

	if err := writeLocalKeyFile(tlsSvrKeyFile, svrKey); err != nil {
		return err
	}

	if err := writeLocalCertFile(tlsClientCertFile, clientCrt); err != nil {
		return err
	}

	if err := writeLocalKeyFile(tlsClientKeyFile, clientKey); err != nil {
		return err
	}

	return nil
}

func writeLocalCertFile(name string, certs ...*x509.Certificate) error {
	return os.WriteFile(name, pkigen.EncodeCerts(certs...), 0o600)
}

func writeLocalKeyFile(name string, key crypto.PrivateKey) error {
	keyPEM, err := pkigen.EncodePrivateKey(key)
	if err != nil {
		return err
	}

	return os.WriteFile(name, keyPEM, 0o600)
}
