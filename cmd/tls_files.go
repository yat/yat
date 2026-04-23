package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

type TLSFiles struct {
	CertFile string
	KeyFile  string
	CAFiles  []string
}

type TLSWatchFunc func(context.Context, *slog.Logger)

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

func (tf TLSFiles) ClientConfig() (*tls.Config, TLSWatchFunc, error) {
	var mu sync.Mutex
	var chains []tls.Certificate
	var roots *x509.CertPool

	load := func() error {
		cc, rr, err := tf.Load()
		if err != nil {
			return err
		}

		mu.Lock()
		defer mu.Unlock()
		chains, roots = cc, rr
		return nil
	}

	if err := load(); err != nil {
		return nil, nil, err
	}

	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			mu.Lock()
			defer mu.Unlock()

			if len(chains) > 0 {
				crt := chains[0]
				return &crt, nil
			}

			return &tls.Certificate{}, nil
		},
	}

	if roots != nil {
		cfg.InsecureSkipVerify = true
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			mu.Lock()
			defer mu.Unlock()

			if len(cs.PeerCertificates) == 0 {
				return errors.New("no server cert")
			}

			opts := x509.VerifyOptions{
				DNSName: cs.ServerName,
				Roots:   roots,
			}

			leaf := cs.PeerCertificates[0]
			if cc := cs.PeerCertificates[1:]; len(cc) > 0 {
				opts.Intermediates = x509.NewCertPool()
				for _, c := range cc {
					opts.Intermediates.AddCert(c)
				}
			}

			_, err := leaf.Verify(opts)
			return err
		}
	}

	return cfg, watch(load), nil
}

func (tf TLSFiles) ServerConfig() (*tls.Config, TLSWatchFunc, error) {
	var mu sync.Mutex
	var chains []tls.Certificate
	var roots *x509.CertPool

	load := func() error {
		cc, rr, err := tf.Load()
		if err != nil {
			return err
		}

		if len(cc) == 0 {
			return errors.New("missing TLS credentials")
		}

		mu.Lock()
		defer mu.Unlock()
		chains, roots = cc, rr
		return nil
	}

	if err := load(); err != nil {
		return nil, nil, err
	}

	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			mu.Lock()
			defer mu.Unlock()

			if len(chains) == 0 {
				return nil, errors.New("missing TLS credentials")
			}

			cfg := &tls.Config{
				Certificates: []tls.Certificate{chains[0]},
				MinVersion:   tls.VersionTLS13,
				NextProtos:   []string{"h2", "http/1.1"},
			}

			if roots != nil {
				cfg.ClientAuth = tls.RequireAndVerifyClientCert
				cfg.ClientCAs = roots
			}

			return cfg, nil
		},
	}

	return cfg, watch(load), nil
}

func watch(load func() error) func(ctx context.Context, logger *slog.Logger) {
	return func(ctx context.Context, logger *slog.Logger) {
		tick := time.NewTicker(10 * time.Second)

		for {
			select {
			case <-ctx.Done():
				return

			case <-tick.C:
				if err := load(); err != nil {
					logger.ErrorContext(ctx, "tls file watch failed", "error", err)
				}
			}
		}
	}
}
