package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"

	"yat.io/yat"
	"yat.io/yat/internal/flagset"
)

type ServeCmd struct {
	AuthFile    string
	BindAddress string
}

// var (
// 	errServeBadTLSFlags = errors.New("-local-tls and -tls-* are mutually exclusive")
// 	errServeNoTLSCreds  = errors.New("missing credentials: set one of -local-tls or -tls-*")
// )

func (cmd ServeCmd) Run(ctx context.Context, logger *slog.Logger, cfg SharedConfig, args []string) error {
	if len(args) != 0 {
		return usageError{
			Usage: "yat serve [flags]",
			Topic: "serve",
		}
	}

	if cfg.LocalDir != "" {
		cmd.AuthFile = filepath.Join(cfg.LocalDir, "rules.yaml")
	}

	if len(cmd.BindAddress) == 0 {
		cmd.BindAddress = cfg.Address
	}

	tlsConfig, err := cfg.NewServerTLSConfig()
	if err != nil {
		return fmt.Errorf("yat serve: %v", err)
	}

	if err := cmd.run(ctx, logger, tlsConfig); err != nil {
		return fmt.Errorf("yat serve: %v", err)
	}

	return nil
}

func (cmd ServeCmd) run(ctx context.Context, logger *slog.Logger, tlsConfig *tls.Config) error {
	l, err := net.Listen("tcp", cmd.BindAddress)
	if err != nil {
		return err
	}

	defer l.Close()

	scfg := yat.ServerConfig{
		Logger: logger,
	}

	if cmd.AuthFile != "" {
		rules, err := yat.ReadAuthFile(cmd.AuthFile)
		if err != nil {
			return err
		}

		scfg.Auth, err = yat.NewAuth(ctx, rules)
		if err != nil {
			return err
		}
	}

	svr, err := yat.NewServer(tlsConfig, scfg)

	if err != nil {
		return err
	}

	logger.InfoContext(ctx, "serve",
		"address", l.Addr().String())

	return svr.Serve(l)
}

func (cmd *ServeCmd) Flags() *flagset.Set {
	flags := flagset.New()
	flags.String(&cmd.AuthFile, "auth")
	flags.String(&cmd.BindAddress, "bind")
	return flags
}

// func (cmd ServeCmd) setupTLS(cfg SharedConfig) (*tls.Config, error) {
// 	var (
// 		hasStaticTLSConfig    = len(cfg.TLSCertFile) > 0 && len(cfg.TLSKeyFile) > 0
// 		hasAnyStaticTLSConfig = len(cfg.TLSCertFile) > 0 || len(cfg.TLSKeyFile) > 0 || len(cfg.TLSCAFile) > 0
// 		hasLocalTLSConfig     = len(cmd.LocalTLSDir) > 0
// 	)

// 	if hasStaticTLSConfig && hasLocalTLSConfig ||
// 		hasLocalTLSConfig && hasAnyStaticTLSConfig {
// 		return nil, errServeBadTLSFlags
// 	}

// 	switch {
// 	case hasStaticTLSConfig:
// 		return cmd.setupStaticTLS(cfg)

// 	case hasLocalTLSConfig:
// 		return cmd.setupLocalTLS(cfg)

// 	default:
// 		return nil, errServeNoTLSCreds
// 	}
// }

// func (cmd ServeCmd) setupLocalTLS(cfg SharedConfig) (*tls.Config, error) {
// 	hostname, _, err := net.SplitHostPort(cfg.Address)
// 	if err != nil {
// 		return nil, err
// 	}

// 	var (
// 		hostnameFile      = filepath.Join(cmd.LocalTLSDir, "hostname")
// 		tlsCAFile         = filepath.Join(cmd.LocalTLSDir, "ca.crt")
// 		tlsSvrCertFile    = filepath.Join(cmd.LocalTLSDir, "server.crt")
// 		tlsSvrKeyFile     = filepath.Join(cmd.LocalTLSDir, "server.key")
// 		tlsClientCertFile = filepath.Join(cmd.LocalTLSDir, "client.crt")
// 		tlsClientKeyFile  = filepath.Join(cmd.LocalTLSDir, "client.key")
// 	)

// 	tlsFiles := []string{
// 		hostnameFile,
// 		tlsCAFile,
// 		tlsSvrCertFile,
// 		tlsSvrKeyFile,
// 		tlsClientCertFile,
// 		tlsClientKeyFile,
// 	}

// 	tlsOK := true
// 	for _, name := range tlsFiles {
// 		if _, err := os.Stat(name); err != nil {
// 			tlsOK = false
// 			break
// 		}
// 	}

// 	if tlsOK {
// 		oldHostname, err := os.ReadFile(hostnameFile)
// 		tlsOK = err == nil && hostname == string(oldHostname)
// 	}

// 	if !tlsOK {
// 		if err := os.MkdirAll(cmd.LocalTLSDir, 0755); err != nil {
// 			return nil, err
// 		}

// 		if err := os.WriteFile(hostnameFile, []byte(hostname), 0o644); err != nil {
// 			return nil, err
// 		}

// 		caCrt, caKey, err := pkigen.NewRoot()
// 		if err != nil {
// 			return nil, err
// 		}

// 		ip := net.ParseIP(hostname)
// 		var san pkigen.CertOpt

// 		switch {
// 		case ip != nil:
// 			san = pkigen.IP(ip)
// 		default:
// 			san = pkigen.DNS(hostname)
// 		}

// 		svrCrt, svrKey, err := pkigen.NewLeaf(caCrt, caKey, san)
// 		if err != nil {
// 			return nil, err
// 		}

// 		clientCrt, clientKey, err := pkigen.NewLeaf(caCrt, caKey, pkigen.CN("yat client"))
// 		if err != nil {
// 			return nil, err
// 		}

// 		if err := writeCertFile(tlsCAFile, caCrt); err != nil {
// 			return nil, err
// 		}

// 		if err := writeCertFile(tlsSvrCertFile, svrCrt); err != nil {
// 			return nil, err
// 		}

// 		if err := writePrivateKeyFile(tlsSvrKeyFile, svrKey); err != nil {
// 			return nil, err
// 		}

// 		if err := writeCertFile(tlsClientCertFile, clientCrt); err != nil {
// 			return nil, err
// 		}

// 		if err := writePrivateKeyFile(tlsClientKeyFile, clientKey); err != nil {
// 			return nil, err
// 		}
// 	}

// 	crt, err := tls.LoadX509KeyPair(tlsSvrCertFile, tlsSvrKeyFile)
// 	if err != nil {
// 		return nil, err
// 	}

// 	tlsConfig := &tls.Config{
// 		Certificates: []tls.Certificate{crt},
// 		MinVersion:   tls.VersionTLS13,
// 		ClientAuth:   tls.RequireAndVerifyClientCert,
// 		ClientCAs:    x509.NewCertPool(),
// 	}

// 	rootCerts, err := os.ReadFile(tlsCAFile)
// 	if err != nil {
// 		return nil, err
// 	}

// 	if !tlsConfig.ClientCAs.AppendCertsFromPEM(rootCerts) {
// 		return nil, fmt.Errorf("read %s: no certificates", tlsCAFile)
// 	}

// 	return tlsConfig, nil
// }

// func (cmd ServeCmd) setupStaticTLS(cfg SharedConfig) (*tls.Config, error) {
// 	crt, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
// 	if err != nil {
// 		return nil, err
// 	}

// 	tlsConfig := &tls.Config{
// 		Certificates: []tls.Certificate{crt},
// 		MinVersion:   tls.VersionTLS13,
// 	}

// 	if len(cfg.TLSCAFile) > 0 {
// 		rootCerts, err := os.ReadFile(cfg.TLSCAFile)
// 		if err != nil {
// 			return nil, err
// 		}

// 		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert

// 		tlsConfig.ClientCAs = x509.NewCertPool()
// 		if !tlsConfig.ClientCAs.AppendCertsFromPEM(rootCerts) {
// 			return nil, fmt.Errorf("read %s: no certificates", cfg.TLSCAFile)
// 		}
// 	}

// 	return tlsConfig, nil
// }

// // writeCertFile PEM-encodes the certificates and writes them to the named file.
// // If the file doesn't exist, it is created with mode 0644.
// func writeCertFile(name string, certs ...*x509.Certificate) error {
// 	return os.WriteFile(name, pkigen.EncodeCerts(certs...), 0644)
// }

// // writePrivateKeyFile PEM-encodes the key and writes it to the named file.
// // If the file doesn't exist, it is created with mode 0600.
// func writePrivateKeyFile(name string, key crypto.PrivateKey) error {
// 	keyPEM, err := pkigen.EncodePrivateKey(key)
// 	if err != nil {
// 		return err
// 	}

// 	return os.WriteFile(name, keyPEM, 0600)
// }
