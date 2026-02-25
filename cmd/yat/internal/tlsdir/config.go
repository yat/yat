// Package tlsdir loads (and reloads) client and server credentials from a local directory.
package tlsdir

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
)

type Config struct {
	dir     string
	mode    string
	base    *tls.Config
	config  atomic.Pointer[tls.Config]
	watched atomic.Bool
}

// LoadClientConfig loads client.crt, client.key, and (if present) ca.crt from the given directory.
func LoadClientConfig(dir string, baseConfig *tls.Config) (*Config, error) {
	c := &Config{
		dir:  dir,
		mode: "client",
		base: baseConfig,
	}

	if err := c.Reload(); err != nil {
		return nil, err
	}

	return c, nil
}

// LoadClientConfig loads server.crt, server.key, and (if present) ca.crt from the given directory.
func LoadServerConfig(dir string, baseConfig *tls.Config) (*Config, error) {
	c := &Config{
		dir:  dir,
		mode: "server",
		base: baseConfig,
	}

	if err := c.Reload(); err != nil {
		return nil, err
	}

	return c, nil
}

// TLSConfig returns the loaded TLS configuration.
// For server configurations, the returned [tls.Config] is updated automatically
// when the configuration is reloaded.
func (c *Config) TLSConfig() *tls.Config {
	if c.config.Load() == nil {
		return nil
	}

	if c.mode == "client" {
		return c.config.Load()
	}

	return &tls.Config{
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return c.config.Load(), nil
		},
	}
}

// Reload reloads the configuration.
func (c *Config) Reload() error {
	if c.dir == "" || c.mode == "" {
		return errors.New("invalid config")
	}

	cfg := c.base.Clone()
	if cfg == nil {
		cfg = new(tls.Config)
	}

	crt, err := tls.LoadX509KeyPair(c.certPath(), c.keyPath())
	if err != nil {
		return err
	}

	cfg.Certificates = []tls.Certificate{crt}

	if c.hasCA() {
		pemCerts, err := os.ReadFile(c.caPath())
		if err != nil {
			return err
		}

		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pemCerts) {
			return errors.New("no roots")
		}

		switch c.mode {
		case "client":
			cfg.RootCAs = roots

		case "server":
			cfg.ClientCAs = roots
			cfg.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}

	c.config.Store(cfg)

	return nil
}

// Watch reloads the configuration when files change.
// If the new configuration is invalid, the old one is retained and the error is logged.
// Watch blocks until the given context is canceled.
// Calling Watch more than once is an error.
func (c *Config) Watch(ctx context.Context, logger *slog.Logger) error {
	if !c.watched.CompareAndSwap(false, true) {
		return errors.New("already watched")
	}

	logger = logger.With("dir", c.dir)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	defer watcher.Close()
	if err := watcher.Add(c.dir); err != nil {
		return err
	}

	var debounce <-chan time.Time

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case err := <-watcher.Errors:
			logger.ErrorContext(ctx, "tls config watch failed", "error", err)

		case evt := <-watcher.Events:
			switch filepath.Base(evt.Name) {
			case "client.crt", "client.key", "server.crt", "server.key", "ca.crt":
			default:
				continue
			}

			debounce = time.After(100 * time.Millisecond)

		case <-debounce:
			debounce = nil
			if err := c.Reload(); err != nil {
				logger.ErrorContext(ctx, "tls config reload failed", "error", err)
			} else {
				logger.InfoContext(ctx, "tls config reloaded")
			}
		}
	}
}

func (c *Config) certPath() string {
	return filepath.Join(c.dir, c.mode+".crt")
}

func (c *Config) keyPath() string {
	return filepath.Join(c.dir, c.mode+".key")
}

func (c *Config) caPath() string {
	return filepath.Join(c.dir, "ca.crt")
}

func (c *Config) hasCA() bool {
	_, err := os.Stat(c.caPath())
	return err == nil
}
