package servertls

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

// DirConfig reads credentials from PEM encoded files in a local directory.
// It reads the server keypair from server.crt and server.key.
// If ca.crt is present, the roots it contains are used to verify client certificates.
type DirConfig struct {
	dir     string
	base    *tls.Config
	config  atomic.Pointer[tls.Config]
	watched atomic.Bool
}

// NewDirConfig loads a server TLS configuration from the given directory.
// If baseConfig is not nil, it is cloned each time the configuration is updated.
// Call [DirConfig.Watch] to automatically reload when files change.
func NewDirConfig(dir string, baseConfig *tls.Config) (*DirConfig, error) {
	d := &DirConfig{
		dir:  dir,
		base: baseConfig,
	}

	if err := d.Reload(); err != nil {
		return nil, err
	}

	return d, nil
}

// TLSConfig returns a TLS configuration backed by the server.crt, server.key, and (optionally) ca.crt files in the configured directory.
// If [DirConfig.Watch] is running, the configuration is reloaded automatically when files change.
func (d *DirConfig) TLSConfig() *tls.Config {
	if d.config.Load() == nil {
		return nil
	}

	return &tls.Config{
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return d.config.Load(), nil
		},
	}
}

// Watch reloads the configuration when files change.
// If the new configuration is invalid, the old one is retained and the error is logged.
// Watch blocks until the given context is canceled.
// Calling Watch more than once is an error.
func (d *DirConfig) Watch(ctx context.Context, logger *slog.Logger) error {
	if !d.watched.CompareAndSwap(false, true) {
		return errors.New("already watched")
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	defer watcher.Close()
	if err := watcher.Add(d.dir); err != nil {
		return err
	}

	var debounce <-chan time.Time

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case err := <-watcher.Errors:
			logger.ErrorContext(ctx, "tls config directory watch failed", "error", err)

		case evt := <-watcher.Events:
			switch filepath.Base(evt.Name) {
			case "server.crt", "server.key", "ca.crt":
			default:
				continue
			}

			debounce = time.After(100 * time.Millisecond)

		case <-debounce:
			debounce = nil
			if err := d.Reload(); err != nil {
				logger.ErrorContext(ctx, "tls config directory reload failed", "error", err)
			} else {
				logger.InfoContext(ctx, "tls config directory reloaded")
			}
		}
	}
}

// Reload reloads the configuration.
func (d *DirConfig) Reload() error {
	cfg := d.base.Clone()
	if cfg == nil {
		cfg = new(tls.Config)
	}

	crt, err := tls.LoadX509KeyPair(d.certPath(), d.keyPath())
	if err != nil {
		return err
	}

	cfg.Certificates = []tls.Certificate{crt}

	if d.hasCA() {
		pemCerts, err := os.ReadFile(d.caPath())
		if err != nil {
			return err
		}

		cfg.ClientCAs = x509.NewCertPool()
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		if !cfg.ClientCAs.AppendCertsFromPEM(pemCerts) {
			return errors.New("no roots")
		}
	}

	d.config.Store(cfg)

	return nil
}

func (d *DirConfig) certPath() string {
	return filepath.Join(d.dir, "server.crt")
}

func (d *DirConfig) keyPath() string {
	return filepath.Join(d.dir, "server.key")
}

func (d *DirConfig) caPath() string {
	return filepath.Join(d.dir, "ca.crt")
}

func (d *DirConfig) hasCA() bool {
	_, err := os.Stat(d.caPath())
	return err == nil
}
