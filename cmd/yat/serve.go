package main

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"yat.io/yat"
	"yat.io/yat/internal/flagset"
	"yat.io/yat/internal/pkigen"
)

type ServeCmd struct {
	Bind        string
	LocalTLSDir string
}

var (
	errServeBadTLSFlags = errors.New("-local-tls and -tls-* are mutually exclusive")
	errServeNoTLSCreds  = errors.New("missing credentials: set one of -local-tls or -tls-*")
)

func (cmd ServeCmd) Run(ctx context.Context, logger *slog.Logger, cfg SharedConfig, args []string) error {
	if len(args) != 0 {
		return usageError{
			Usage: "yat serve [flags]",
			Topic: "serve",
		}
	}

	tlsConfig, err := cmd.setupTLS(cfg)
	if err != nil {
		return fmt.Errorf("yat serve: %v", err)
	}

	if len(cmd.Bind) == 0 {
		cmd.Bind = cfg.Address
	}

	if err := cmd.run(ctx, logger, tlsConfig); err != nil {
		return fmt.Errorf("yat serve: %v", err)
	}

	return nil
}

func (cmd ServeCmd) run(ctx context.Context, logger *slog.Logger, tlsConfig *tls.Config) error {
	l, err := net.Listen("tcp", cmd.Bind)
	if err != nil {
		return err
	}

	defer l.Close()

	rr := yat.NewRouter()

	logger.InfoContext(ctx, "serve",
		"address", l.Addr().String())

	for {
		nc, err := l.Accept()
		if err != nil {
			break
		}

		go func() {
			defer nc.Close()

			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			logger := logger.With(
				"conn", uuid.New().String(),
				"remote", nc.RemoteAddr().String(),
				"local", nc.LocalAddr().String())

			start := time.Now()
			logger.DebugContext(ctx, "connection opened")

			conn := tls.Server(nc, tlsConfig)
			if err := conn.HandshakeContext(ctx); err != nil {
				logger.DebugContext(ctx, "handshake failed", "error", err)
				return
			}

			defer func() {
				logger.DebugContext(ctx, "connection closed",
					"elapsed", time.Since(start).Seconds())
			}()

			err := yat.Serve(ctx, conn, rr)
			if err == io.EOF {
				err = nil
			}

			if err != nil {
				logger.ErrorContext(ctx, "connection error", "error", err)
			}
		}()
	}

	return nil
}

func (cmd *ServeCmd) Flags() *flagset.Set {
	flags := flagset.New()
	flags.String(&cmd.Bind, "bind")
	flags.String(&cmd.LocalTLSDir, "local-tls")
	return flags
}

func (cmd ServeCmd) setupTLS(cfg SharedConfig) (*tls.Config, error) {
	var (
		hasStaticTLSConfig    = len(cfg.TLSCertFile) > 0 && len(cfg.TLSKeyFile) > 0
		hasAnyStaticTLSConfig = len(cfg.TLSCertFile) > 0 || len(cfg.TLSKeyFile) > 0 || len(cfg.TLSCAFile) > 0
		hasLocalTLSConfig     = len(cmd.LocalTLSDir) > 0
	)

	if hasStaticTLSConfig && hasLocalTLSConfig ||
		hasLocalTLSConfig && hasAnyStaticTLSConfig {
		return nil, errServeBadTLSFlags
	}

	switch {
	case hasStaticTLSConfig:
		return cmd.setupStaticTLS(cfg)

	case hasLocalTLSConfig:
		return cmd.setupLocalTLS(cfg)

	default:
		return nil, errServeNoTLSCreds
	}
}

func (cmd ServeCmd) setupLocalTLS(cfg SharedConfig) (*tls.Config, error) {
	hostname, _, err := net.SplitHostPort(cfg.Address)
	if err != nil {
		return nil, err
	}

	var (
		hostnameFile      = filepath.Join(cmd.LocalTLSDir, "hostname")
		tlsCAFile         = filepath.Join(cmd.LocalTLSDir, "ca.crt")
		tlsSvrCertFile    = filepath.Join(cmd.LocalTLSDir, "server.crt")
		tlsSvrKeyFile     = filepath.Join(cmd.LocalTLSDir, "server.key")
		tlsClientCertFile = filepath.Join(cmd.LocalTLSDir, "client.crt")
		tlsClientKeyFile  = filepath.Join(cmd.LocalTLSDir, "client.key")
	)

	tlsFiles := []string{
		hostnameFile,
		tlsCAFile,
		tlsSvrCertFile,
		tlsSvrKeyFile,
		tlsClientCertFile,
		tlsClientKeyFile,
	}

	tlsOK := true
	for _, name := range tlsFiles {
		if _, err := os.Stat(name); err != nil {
			tlsOK = false
			break
		}
	}

	if tlsOK {
		oldHostname, err := os.ReadFile(hostnameFile)
		tlsOK = err == nil && hostname == string(oldHostname)
	}

	if !tlsOK {
		if err := os.MkdirAll(cmd.LocalTLSDir, 0755); err != nil {
			return nil, err
		}

		if err := os.WriteFile(hostnameFile, []byte(hostname), 0o644); err != nil {
			return nil, err
		}

		caCrt, caKey, err := pkigen.NewRoot()
		if err != nil {
			return nil, err
		}

		ip := net.ParseIP(hostname)
		var san pkigen.CertOpt

		switch {
		case ip != nil:
			san = pkigen.IP(ip)
		default:
			san = pkigen.DNS(hostname)
		}

		svrCrt, svrKey, err := pkigen.NewLeaf(caCrt, caKey, san)
		if err != nil {
			return nil, err
		}

		clientCrt, clientKey, err := pkigen.NewLeaf(caCrt, caKey, pkigen.CN("yat client"))
		if err != nil {
			return nil, err
		}

		if err := writeCertFile(tlsCAFile, caCrt); err != nil {
			return nil, err
		}

		if err := writeCertFile(tlsSvrCertFile, svrCrt); err != nil {
			return nil, err
		}

		if err := writePrivateKeyFile(tlsSvrKeyFile, svrKey); err != nil {
			return nil, err
		}

		if err := writeCertFile(tlsClientCertFile, clientCrt); err != nil {
			return nil, err
		}

		if err := writePrivateKeyFile(tlsClientKeyFile, clientKey); err != nil {
			return nil, err
		}
	}

	crt, err := tls.LoadX509KeyPair(tlsSvrCertFile, tlsSvrKeyFile)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{crt},
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    x509.NewCertPool(),
	}

	rootCerts, err := os.ReadFile(tlsCAFile)
	if err != nil {
		return nil, err
	}

	if !tlsConfig.ClientCAs.AppendCertsFromPEM(rootCerts) {
		return nil, fmt.Errorf("read %s: no certificates", tlsCAFile)
	}

	return tlsConfig, nil
}

func (cmd ServeCmd) setupStaticTLS(cfg SharedConfig) (*tls.Config, error) {
	crt, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{crt},
		MinVersion:   tls.VersionTLS13,
	}

	if len(cfg.TLSCAFile) > 0 {
		rootCerts, err := os.ReadFile(cfg.TLSCAFile)
		if err != nil {
			return nil, err
		}

		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert

		tlsConfig.ClientCAs = x509.NewCertPool()
		if !tlsConfig.ClientCAs.AppendCertsFromPEM(rootCerts) {
			return nil, fmt.Errorf("read %s: no certificates", cfg.TLSCAFile)
		}
	}

	return tlsConfig, nil
}

// writeCertFile PEM-encodes the certificates and writes them to the named file.
// If the file doesn't exist, it is created with mode 0644.
func writeCertFile(name string, certs ...*x509.Certificate) error {
	return os.WriteFile(name, pkigen.EncodeCerts(certs...), 0644)
}

// writePrivateKeyFile PEM-encodes the key and writes it to the named file.
// If the file doesn't exist, it is created with mode 0600.
func writePrivateKeyFile(name string, key crypto.PrivateKey) error {
	keyPEM, err := pkigen.EncodePrivateKey(key)
	if err != nil {
		return err
	}

	return os.WriteFile(name, keyPEM, 0600)
}
