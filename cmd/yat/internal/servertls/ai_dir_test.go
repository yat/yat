package servertls_test

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
	"strings"
	"testing"
	"time"

	"yat.io/yat/cmd/yat/internal/pkigen"
	"yat.io/yat/cmd/yat/internal/servertls"
)

type certBundle struct {
	serverCertPEM []byte
	serverKeyPEM  []byte
	caCertPEM     []byte
}

func TestNewDirConfig(t *testing.T) {
	t.Run("with ca", func(t *testing.T) {
		dir := t.TempDir()
		writeBundle(t, dir, newBundle(t, "server-with-ca"), true)

		d, err := servertls.NewDirConfig(dir, nil)
		if err != nil {
			t.Fatal(err)
		}

		cfg := activeConfig(t, d)
		if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
			t.Fatalf("ClientAuth %v != %v", cfg.ClientAuth, tls.RequireAndVerifyClientCert)
		}

		if cfg.ClientCAs == nil {
			t.Fatal("ClientCAs is nil")
		}
	})

	t.Run("without ca", func(t *testing.T) {
		dir := t.TempDir()
		writeBundle(t, dir, newBundle(t, "server-no-ca"), false)

		d, err := servertls.NewDirConfig(dir, nil)
		if err != nil {
			t.Fatal(err)
		}

		cfg := activeConfig(t, d)
		if cfg.ClientAuth != tls.NoClientCert {
			t.Fatalf("ClientAuth %v != %v", cfg.ClientAuth, tls.NoClientCert)
		}

		if cfg.ClientCAs != nil {
			t.Fatal("ClientCAs is non-nil")
		}
	})

	t.Run("missing key file", func(t *testing.T) {
		dir := t.TempDir()
		b := newBundle(t, "server-missing-key")

		if err := os.WriteFile(filepath.Join(dir, "server.crt"), b.serverCertPEM, 0o600); err != nil {
			t.Fatal(err)
		}

		if _, err := servertls.NewDirConfig(dir, nil); err == nil {
			t.Fatal("no error")
		}
	})

	t.Run("clones base config", func(t *testing.T) {
		dir := t.TempDir()
		writeBundle(t, dir, newBundle(t, "server-with-base"), true)

		base := &tls.Config{
			MinVersion: tls.VersionTLS13,
			NextProtos: []string{"y0"},
		}

		d, err := servertls.NewDirConfig(dir, base)
		if err != nil {
			t.Fatal(err)
		}

		cfg := activeConfig(t, d)
		if cfg == base {
			t.Fatal("config aliases base")
		}

		if cfg.MinVersion != tls.VersionTLS13 {
			t.Fatalf("MinVersion %v != %v", cfg.MinVersion, tls.VersionTLS13)
		}

		if !slices.Equal(cfg.NextProtos, []string{"y0"}) {
			t.Fatalf("NextProtos %v != %v", cfg.NextProtos, []string{"y0"})
		}

		if len(base.Certificates) != 0 {
			t.Fatal("base config was mutated")
		}

		if base.ClientAuth != tls.NoClientCert {
			t.Fatal("base config client auth was mutated")
		}
	})
}

func TestDirConfig_TLSConfig_ZeroValue(t *testing.T) {
	var d servertls.DirConfig
	if d.TLSConfig() != nil {
		t.Fatal("unexpected non-nil TLSConfig")
	}
}

func TestDirConfig_Watch_AlreadyWatched(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, newBundle(t, "server-watch-already"), true)

	d, err := servertls.NewDirConfig(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.DiscardHandler)

	ctx1, cancel1 := context.WithCancel(context.Background())
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel1()
	defer cancel2()

	done := make(chan error, 2)
	go func() { done <- d.Watch(ctx1, logger) }()
	go func() { done <- d.Watch(ctx2, logger) }()

	var firstErr error
	select {
	case firstErr = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watch did not return")
	}

	if firstErr == nil || firstErr.Error() != "already watched" {
		t.Fatalf("error %v != %q", firstErr, "already watched")
	}

	cancel1()
	cancel2()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watch did not return after cancel")
	}
}

func TestDirConfig_Watch_Cancel(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, newBundle(t, "server-watch-cancel"), true)

	d, err := servertls.NewDirConfig(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)

	go func() {
		done <- d.Watch(ctx, slog.New(slog.DiscardHandler))
	}()

	select {
	case err := <-done:
		t.Fatalf("watch exited early: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error %v is not context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watch did not return")
	}
}

func TestDirConfig_Watch_ReloadsOnTLSFileChanges(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, newBundle(t, "server-before-reload"), true)

	d, err := servertls.NewDirConfig(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	cancel, done := startWatch(t, d)
	defer stopWatch(t, cancel, done)

	before := activeServerCN(t, d)
	afterBundle := newBundle(t, "server-after-reload")

	// Update key+cert quickly; Watch debounces and should reload the final pair.
	if err := os.WriteFile(filepath.Join(dir, "server.key"), afterBundle.serverKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "server.crt"), afterBundle.serverCertPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 3*time.Second, func() bool {
		return activeServerCN(t, d) != before
	})

	if got := activeServerCN(t, d); got != "server-after-reload" {
		t.Fatalf("common name %q != %q", got, "server-after-reload")
	}
}

func TestDirConfig_Watch_DebouncesKeyAndCertUpdate(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, newBundle(t, "server-before-debounce"), true)

	d, err := servertls.NewDirConfig(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	cancel, done := startWatchWithLogger(t, d, logger)
	defer stopWatch(t, cancel, done)

	afterBundle := newBundle(t, "server-after-debounce")

	if err := os.WriteFile(filepath.Join(dir, "server.key"), afterBundle.serverKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if err := os.WriteFile(filepath.Join(dir, "server.crt"), afterBundle.serverCertPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 3*time.Second, func() bool {
		return activeServerCN(t, d) == "server-after-debounce"
	})

	if strings.Contains(logs.String(), "tls config directory reload failed") {
		t.Fatalf("unexpected reload failure log:\n%s", logs.String())
	}
}

func TestDirConfig_Watch_IgnoresUnrelatedFiles(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, newBundle(t, "server-unrelated"), true)

	d, err := servertls.NewDirConfig(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	cancel, done := startWatch(t, d)
	defer stopWatch(t, cancel, done)

	before := activeConfig(t, d)

	if err := os.WriteFile(filepath.Join(dir, "note.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	time.Sleep(300 * time.Millisecond)

	after := activeConfig(t, d)
	if after != before {
		t.Fatal("tls config changed after unrelated file write")
	}
}

func TestDirConfig_Watch_ReloadFailureKeepsLastGoodConfig(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, newBundle(t, "server-good"), true)

	d, err := servertls.NewDirConfig(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	cancel, done := startWatch(t, d)
	defer stopWatch(t, cancel, done)

	before := activeConfig(t, d)

	if err := os.WriteFile(filepath.Join(dir, "server.crt"), []byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}

	time.Sleep(300 * time.Millisecond)

	after := activeConfig(t, d)
	if after != before {
		t.Fatal("tls config changed after failed reload")
	}
}

func TestDirConfig_Watch_ReloadKeepsBaseConfig(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, newBundle(t, "server-base-before"), true)

	base := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"y0"},
	}

	d, err := servertls.NewDirConfig(dir, base)
	if err != nil {
		t.Fatal(err)
	}

	cancel, done := startWatch(t, d)
	defer stopWatch(t, cancel, done)

	afterBundle := newBundle(t, "server-base-after")
	if err := os.WriteFile(filepath.Join(dir, "server.key"), afterBundle.serverKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "server.crt"), afterBundle.serverCertPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 3*time.Second, func() bool {
		return activeServerCN(t, d) == "server-base-after"
	})

	cfg := activeConfig(t, d)
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion %v != %v", cfg.MinVersion, tls.VersionTLS13)
	}
	if !slices.Equal(cfg.NextProtos, []string{"y0"}) {
		t.Fatalf("NextProtos %v != %v", cfg.NextProtos, []string{"y0"})
	}
}

func newBundle(t *testing.T, serverCN string) certBundle {
	t.Helper()

	caCrt, caKey, err := pkigen.NewRoot()
	if err != nil {
		t.Fatal(err)
	}

	serverCrt, serverKey, err := pkigen.NewLeaf(caCrt, caKey, pkigen.CN(serverCN))
	if err != nil {
		t.Fatal(err)
	}

	serverKeyPEM, err := pkigen.EncodePrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}

	return certBundle{
		serverCertPEM: pkigen.EncodeCerts(serverCrt),
		serverKeyPEM:  serverKeyPEM,
		caCertPEM:     pkigen.EncodeCerts(caCrt),
	}
}

func writeBundle(t *testing.T, dir string, b certBundle, withCA bool) {
	t.Helper()

	if err := os.WriteFile(filepath.Join(dir, "server.crt"), b.serverCertPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "server.key"), b.serverKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	caPath := filepath.Join(dir, "ca.crt")
	if withCA {
		if err := os.WriteFile(caPath, b.caCertPEM, 0o600); err != nil {
			t.Fatal(err)
		}
	} else {
		if err := os.Remove(caPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	}
}

func activeConfig(t *testing.T, d *servertls.DirConfig) *tls.Config {
	t.Helper()

	tc := d.TLSConfig()
	if tc == nil {
		t.Fatal("TLSConfig is nil")
	}

	cfg, err := tc.GetConfigForClient(nil)
	if err != nil {
		t.Fatal(err)
	}

	if cfg == nil {
		t.Fatal("active config is nil")
	}

	return cfg
}

func activeServerCN(t *testing.T, d *servertls.DirConfig) string {
	t.Helper()

	cfg := activeConfig(t, d)
	if len(cfg.Certificates) == 0 {
		t.Fatal("no certificates")
	}

	if len(cfg.Certificates[0].Certificate) == 0 {
		t.Fatal("empty certificate chain")
	}

	crt, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	return crt.Subject.CommonName
}

func startWatch(t *testing.T, d *servertls.DirConfig) (context.CancelFunc, <-chan error) {
	return startWatchWithLogger(t, d, slog.New(slog.DiscardHandler))
}

func startWatchWithLogger(t *testing.T, d *servertls.DirConfig, logger *slog.Logger) (context.CancelFunc, <-chan error) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)

	go func() {
		done <- d.Watch(ctx, logger)
	}()

	// Let Watch initialize and fail fast if it exits immediately.
	select {
	case err := <-done:
		t.Fatalf("watch exited early: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	return cancel, done
}

func stopWatch(t *testing.T, cancel context.CancelFunc, done <-chan error) {
	t.Helper()

	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error %v is not context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watch did not return")
	}
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}

		time.Sleep(10 * time.Millisecond)
	}

	if cond() {
		return
	}

	t.Fatal("timeout")
}
