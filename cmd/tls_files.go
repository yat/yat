package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

type TLSFiles struct {
	CertFile string
	KeyFile  string
	CAFiles  []string
}

func (tf TLSFiles) Load() (chains []tls.Certificate, roots *x509.CertPool, err error) {
	haveCertFile := tf.CertFile != ""
	haveKeyFile := tf.KeyFile != ""
	haveCAFiles := len(tf.CAFiles) > 0

	if haveCertFile != haveKeyFile {
		err = errors.New("-tls-cert-file and -tls-key-file must be set together")
		return
	}

	if haveCertFile {
		crt, err := tls.LoadX509KeyPair(tf.CertFile, tf.KeyFile)
		if err != nil {
			return nil, nil, err
		}

		chains = []tls.Certificate{crt}
	}

	if haveCAFiles {
		roots = x509.NewCertPool()
		for _, name := range tf.CAFiles {
			raw, err := os.ReadFile(name)
			if err != nil {
				return nil, nil, err
			}

			if !roots.AppendCertsFromPEM(raw) {
				return nil, nil, fmt.Errorf("parse %s: no roots", name)
			}
		}
	}

	return
}

func (tf TLSFiles) ClientConfig() (*tls.Config, error) {
	chains, roots, err := tf.Load()
	if err != nil {
		return nil, err
	}

	cfg := &tls.Config{
		Certificates: chains,
		MinVersion:   tls.VersionTLS13,
	}

	if roots != nil {
		cfg.RootCAs = roots
	}

	return cfg, err
}

func (tf TLSFiles) ServerConfig() (*tls.Config, error) {
	chains, roots, err := tf.Load()
	if err != nil {
		return nil, err
	}

	if len(chains) == 0 {
		return nil, errors.New("missing TLS credentials")
	}

	cfg := &tls.Config{
		Certificates: chains,
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2", "http/1.1"},
	}

	if roots != nil {
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		cfg.ClientCAs = roots
	}

	return cfg, nil
}
