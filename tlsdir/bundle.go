// Package tlsdir loads (and reloads) TLS credentials from a local directory.
package tlsdir

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

type Bundle struct {
	dir   string
	base  *tls.Config
	hasCA bool

	mu    sync.Mutex
	certs []tls.Certificate
	roots *x509.CertPool

	certBytes []byte
	keyBytes  []byte
	caBytes   []byte
}

// Load loads TLS credentials from tls.crt, tls.key,
// and (optionally) ca.crt in the given directory.
func Load(dir string, base *tls.Config) (*Bundle, error) {
	if base == nil {
		base = &tls.Config{}
	}

	if len(base.Certificates) != 0 {
		return nil, errors.New("base config includes certificates")
	}

	if base.GetCertificate != nil {
		return nil, errors.New("base config includes a GetCertificate callback")
	}

	if base.GetClientCertificate != nil {
		return nil, errors.New("base config includes a GetClientCertificate callback")
	}

	if base.RootCAs != nil || base.ClientCAs != nil {
		return nil, errors.New("base config includes roots")
	}

	if base.ClientAuth != tls.NoClientCert {
		return nil, errors.New("base config includes a client auth policy")
	}

	b := &Bundle{
		dir:  dir,
		base: base,
	}

	_, err := os.Stat(b.caPath())
	b.hasCA = err == nil

	if err := b.Reload(); err != nil {
		return nil, err
	}

	return b, nil
}

// Reload reloads the bundle.
func (b *Bundle) Reload() error {
	crtBytes, keyBytes, caBytes, err := b.readFiles()
	if err != nil {
		return err
	}

	return b.load(crtBytes, keyBytes, caBytes)
}

// Watch checks the bundle files every few seconds and reloads the bundle if they change.
// If the bundle can't be reloaded, the old credentials are retained and an error is logged.
// Watch blocks until the given context is canceled.
// Calling Watch more than once is an error.
func (b *Bundle) Watch(ctx context.Context, logger *slog.Logger) error {
	logger = logger.With("dir", b.dir)
	tick := time.NewTicker(10 * time.Second)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-tick.C:
			newCrt, newKey, newCA, err := b.readFiles()
			if err != nil {
				logger.ErrorContext(ctx, "tls bundle read failed", "error", err)
				continue
			}

			if b.same(newCrt, newKey, newCA) {
				continue
			}

			logger.DebugContext(ctx, "tls bundle files changed")
			if err := b.load(newCrt, newKey, newCA); err != nil {
				logger.ErrorContext(ctx, "tls bundle load failed", "error", err)
				continue
			}
		}
	}
}

// ClientConfig returns a client TLS configuration.
func (b *Bundle) ClientConfig() *tls.Config {
	cfg := b.base.Clone()

	b.mu.Lock()
	defer b.mu.Unlock()

	cfg.Certificates = slices.Clone(b.certs)

	if b.roots != nil {
		cfg.RootCAs = b.roots.Clone()

	}

	return cfg
}

// ServerConfig returns a server TLS configuration.
// The returned config sets only GetConfigForClient,
// which returns a fresh bundle config when it is called.
func (b *Bundle) ServerConfig() *tls.Config {
	return &tls.Config{
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			cfg := b.base.Clone()

			b.mu.Lock()
			defer b.mu.Unlock()

			cfg.Certificates = slices.Clone(b.certs)

			if b.roots != nil {
				cfg.ClientAuth = tls.RequireAndVerifyClientCert
				cfg.ClientCAs = b.roots.Clone()
			}

			return cfg, nil
		},
	}
}

func (b *Bundle) same(certBytes, keyBytes, caBytes []byte) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Equal(b.certBytes, certBytes) &&
		bytes.Equal(b.keyBytes, keyBytes) &&
		bytes.Equal(b.caBytes, caBytes)
}

func (b *Bundle) load(certBytes, keyBytes, caBytes []byte) error {
	crt, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return err
	}

	// optional ca
	var roots *x509.CertPool

	if b.hasCA {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(caBytes) {
			return errors.New("no roots")
		}
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	b.certs = []tls.Certificate{crt}
	b.roots = roots
	b.certBytes = certBytes
	b.keyBytes = keyBytes
	b.caBytes = caBytes

	return nil
}

func (b *Bundle) readFiles() (certBytes, keyBytes, caBytes []byte, err error) {
	certBytes, err = os.ReadFile(b.certPath())
	if err != nil {
		return
	}

	keyBytes, err = os.ReadFile(b.keyPath())
	if err != nil {
		return
	}

	if b.hasCA {
		caBytes, err = os.ReadFile(b.caPath())
	}

	return
}

func (b *Bundle) certPath() string {
	return filepath.Join(b.dir, "tls.crt")
}

func (b *Bundle) keyPath() string {
	return filepath.Join(b.dir, "tls.key")
}

func (b *Bundle) caPath() string {
	return filepath.Join(b.dir, "ca.crt")
}
