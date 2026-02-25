package tlsdir_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"yat.io/yat/cmd/yat/internal/pkigen"
	"yat.io/yat/cmd/yat/internal/tlsdir"
)

type certBundle struct {
	serverCertPEM []byte
	serverKeyPEM  []byte
	clientCertPEM []byte
	clientKeyPEM  []byte
	caCertPEM     []byte
}

func TestLoadServerConfig(t *testing.T) {
	t.Run("with ca", func(t *testing.T) {
		dir := t.TempDir()
		writeBundle(t, dir, newBundle(t, "server-with-ca", "client-with-ca"), true)

		c, err := tlsdir.LoadServerConfig(dir, nil)
		if err != nil {
			t.Fatal(err)
		}

		cfg := activeServerConfig(t, c)
		if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
			t.Fatalf("ClientAuth %v != %v", cfg.ClientAuth, tls.RequireAndVerifyClientCert)
		}

		if cfg.ClientCAs == nil {
			t.Fatal("ClientCAs is nil")
		}
	})

	t.Run("without ca", func(t *testing.T) {
		dir := t.TempDir()
		writeBundle(t, dir, newBundle(t, "server-no-ca", "client-no-ca"), false)

		c, err := tlsdir.LoadServerConfig(dir, nil)
		if err != nil {
			t.Fatal(err)
		}

		cfg := activeServerConfig(t, c)
		if cfg.ClientAuth != tls.NoClientCert {
			t.Fatalf("ClientAuth %v != %v", cfg.ClientAuth, tls.NoClientCert)
		}

		if cfg.ClientCAs != nil {
			t.Fatal("ClientCAs is non-nil")
		}
	})

	t.Run("missing key file", func(t *testing.T) {
		dir := t.TempDir()
		b := newBundle(t, "server-missing-key", "client-missing-key")

		if err := os.WriteFile(filepath.Join(dir, "server.crt"), b.serverCertPEM, 0o600); err != nil {
			t.Fatal(err)
		}

		if _, err := tlsdir.LoadServerConfig(dir, nil); err == nil {
			t.Fatal("no error")
		}
	})

	t.Run("clones base config", func(t *testing.T) {
		dir := t.TempDir()
		writeBundle(t, dir, newBundle(t, "server-with-base", "client-with-base"), true)

		base := &tls.Config{
			MinVersion: tls.VersionTLS13,
			NextProtos: []string{"y0"},
		}

		c, err := tlsdir.LoadServerConfig(dir, base)
		if err != nil {
			t.Fatal(err)
		}

		cfg := activeServerConfig(t, c)
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

func TestLoadClientConfig(t *testing.T) {
	t.Run("with ca", func(t *testing.T) {
		dir := t.TempDir()
		writeBundle(t, dir, newBundle(t, "server-client-with-ca", "client-with-ca"), true)

		c, err := tlsdir.LoadClientConfig(dir, nil)
		if err != nil {
			t.Fatal(err)
		}

		cfg := activeClientConfig(t, c)
		if cfg.RootCAs == nil {
			t.Fatal("RootCAs is nil")
		}
	})

	t.Run("without ca", func(t *testing.T) {
		dir := t.TempDir()
		writeBundle(t, dir, newBundle(t, "server-client-no-ca", "client-no-ca"), false)

		c, err := tlsdir.LoadClientConfig(dir, nil)
		if err != nil {
			t.Fatal(err)
		}

		cfg := activeClientConfig(t, c)
		if cfg.RootCAs != nil {
			t.Fatal("RootCAs is non-nil")
		}
	})

	t.Run("missing key file", func(t *testing.T) {
		dir := t.TempDir()
		b := newBundle(t, "server-client-missing-key", "client-missing-key")

		if err := os.WriteFile(filepath.Join(dir, "client.crt"), b.clientCertPEM, 0o600); err != nil {
			t.Fatal(err)
		}

		if _, err := tlsdir.LoadClientConfig(dir, nil); err == nil {
			t.Fatal("no error")
		}
	})

	t.Run("clones base config", func(t *testing.T) {
		dir := t.TempDir()
		writeBundle(t, dir, newBundle(t, "server-client-base", "client-with-base"), true)

		base := &tls.Config{
			MinVersion: tls.VersionTLS13,
			NextProtos: []string{"y0"},
		}

		c, err := tlsdir.LoadClientConfig(dir, base)
		if err != nil {
			t.Fatal(err)
		}

		cfg := activeClientConfig(t, c)
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

		if base.RootCAs != nil {
			t.Fatal("base config roots were mutated")
		}
	})
}

func TestConfig_TLSConfig_ZeroValue(t *testing.T) {
	var c tlsdir.Config
	if c.TLSConfig() != nil {
		t.Fatal("unexpected non-nil TLSConfig")
	}
}

func TestConfig_Watch_AlreadyWatched(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, newBundle(t, "server-watch-already", "client-watch-already"), true)

	c, err := tlsdir.LoadServerConfig(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.DiscardHandler)

	ctx1, cancel1 := context.WithCancel(context.Background())
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel1()
	defer cancel2()

	done := make(chan error, 2)
	go func() { done <- c.Watch(ctx1, logger) }()
	go func() { done <- c.Watch(ctx2, logger) }()

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

func TestConfig_Watch_Cancel(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, newBundle(t, "server-watch-cancel", "client-watch-cancel"), true)

	c, err := tlsdir.LoadClientConfig(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)

	go func() {
		done <- c.Watch(ctx, slog.New(slog.DiscardHandler))
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

func TestConfig_Watch_IgnoresUnrelatedFiles(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, newBundle(t, "server-unrelated", "client-unrelated"), true)

	c, err := tlsdir.LoadClientConfig(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	cancel, done := startWatch(t, c)
	defer stopWatch(t, cancel, done)

	before := activeClientConfig(t, c)

	if err := os.WriteFile(filepath.Join(dir, "note.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	time.Sleep(300 * time.Millisecond)

	after := activeClientConfig(t, c)
	if after != before {
		t.Fatal("tls config changed after unrelated file write")
	}
}

func TestConfig_ReloadFailureKeepsLastGoodConfig_Server(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, newBundle(t, "server-good", "client-good"), true)

	c, err := tlsdir.LoadServerConfig(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	before := activeServerConfig(t, c)

	if err := os.WriteFile(filepath.Join(dir, "server.crt"), []byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := c.Reload(); err == nil {
		t.Fatal("no error")
	}

	after := activeServerConfig(t, c)
	if after != before {
		t.Fatal("tls config changed after failed reload")
	}
}

func TestConfig_ReloadFailureKeepsLastGoodConfig_Client(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, newBundle(t, "server-good-client", "client-good"), true)

	c, err := tlsdir.LoadClientConfig(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	before := activeClientConfig(t, c)

	if err := os.WriteFile(filepath.Join(dir, "client.crt"), []byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := c.Reload(); err == nil {
		t.Fatal("no error")
	}

	after := activeClientConfig(t, c)
	if after != before {
		t.Fatal("tls config changed after failed reload")
	}
}

func TestConfig_ClientAndServerHandshake_Success(t *testing.T) {
	dir := t.TempDir()
	b := newBundle(t, "server-handshake-ok", "client-handshake-ok")
	writeBundle(t, dir, b, true)

	serverCfg, err := tlsdir.LoadServerConfig(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	clientCfg, err := tlsdir.LoadClientConfig(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := handshake(serverCfg, clientCfg, "server-handshake-ok"); err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
}

func TestConfig_ClientAndServerHandshake_ClientCertRejected(t *testing.T) {
	dir := t.TempDir()
	b := newBundle(t, "server-handshake-reject", "client-handshake-reject")
	writeBundle(t, dir, b, true)

	other := newBundle(t, "server-other", "client-other")
	if err := os.WriteFile(filepath.Join(dir, "client.crt"), other.clientCertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "client.key"), other.clientKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	serverCfg, err := tlsdir.LoadServerConfig(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	clientCfg, err := tlsdir.LoadClientConfig(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := handshake(serverCfg, clientCfg, "server-handshake-reject"); err == nil {
		t.Fatal("no error")
	}
}

func TestConfig_Watch_ReloadsClientAndServerAndHandshakeStillWorks(t *testing.T) {
	dir := t.TempDir()
	beforeBundle := newBundle(t, "server-before-reload", "client-before-reload")
	writeBundle(t, dir, beforeBundle, true)

	serverCfg, err := tlsdir.LoadServerConfig(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	clientCfg, err := tlsdir.LoadClientConfig(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := handshake(serverCfg, clientCfg, "server-before-reload"); err != nil {
		t.Fatalf("initial handshake failed: %v", err)
	}

	serverCancel, serverDone := startWatch(t, serverCfg)
	defer stopWatch(t, serverCancel, serverDone)

	clientCancel, clientDone := startWatch(t, clientCfg)
	defer stopWatch(t, clientCancel, clientDone)

	afterBundle := newBundle(t, "server-after-reload", "client-after-reload")

	if err := os.WriteFile(filepath.Join(dir, "server.key"), afterBundle.serverKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "server.crt"), afterBundle.serverCertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "client.key"), afterBundle.clientKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "client.crt"), afterBundle.clientCertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), afterBundle.caCertPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 3*time.Second, func() bool {
		return activeServerCN(t, serverCfg) == "server-after-reload" &&
			activeClientCN(t, clientCfg) == "client-after-reload"
	})

	if err := handshake(serverCfg, clientCfg, "server-after-reload"); err != nil {
		t.Fatalf("handshake after reload failed: %v", err)
	}
}

func newBundle(t *testing.T, serverCN string, clientCN string) certBundle {
	t.Helper()

	caCrt, caKey, err := pkigen.NewRoot()
	if err != nil {
		t.Fatal(err)
	}

	serverCrt, serverKey, err := pkigen.NewLeaf(caCrt, caKey, pkigen.CN(serverCN), pkigen.DNS(serverCN))
	if err != nil {
		t.Fatal(err)
	}

	clientCrt, clientKey, err := pkigen.NewLeaf(caCrt, caKey, pkigen.CN(clientCN))
	if err != nil {
		t.Fatal(err)
	}

	serverKeyPEM, err := pkigen.EncodePrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}

	clientKeyPEM, err := pkigen.EncodePrivateKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}

	return certBundle{
		serverCertPEM: pkigen.EncodeCerts(serverCrt),
		serverKeyPEM:  serverKeyPEM,
		clientCertPEM: pkigen.EncodeCerts(clientCrt),
		clientKeyPEM:  clientKeyPEM,
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

	if err := os.WriteFile(filepath.Join(dir, "client.crt"), b.clientCertPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "client.key"), b.clientKeyPEM, 0o600); err != nil {
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

func activeServerConfig(t *testing.T, c *tlsdir.Config) *tls.Config {
	t.Helper()

	tc := c.TLSConfig()
	if tc == nil {
		t.Fatal("TLSConfig is nil")
	}

	if tc.GetConfigForClient == nil {
		t.Fatal("GetConfigForClient is nil")
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

func activeClientConfig(t *testing.T, c *tlsdir.Config) *tls.Config {
	t.Helper()

	cfg := c.TLSConfig()
	if cfg == nil {
		t.Fatal("TLSConfig is nil")
	}

	return cfg
}

func activeServerCN(t *testing.T, c *tlsdir.Config) string {
	t.Helper()
	return configLeafCN(t, activeServerConfig(t, c))
}

func activeClientCN(t *testing.T, c *tlsdir.Config) string {
	t.Helper()
	return configLeafCN(t, activeClientConfig(t, c))
}

func configLeafCN(t *testing.T, cfg *tls.Config) string {
	t.Helper()

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

func startWatch(t *testing.T, c *tlsdir.Config) (context.CancelFunc, <-chan error) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)

	go func() {
		done <- c.Watch(ctx, slog.New(slog.DiscardHandler))
	}()

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

func handshake(serverCfg *tlsdir.Config, clientCfg *tlsdir.Config, serverName string) error {
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg.TLSConfig())
	if err != nil {
		return err
	}
	defer listener.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()

		serverDone <- conn.(*tls.Conn).Handshake()
	}()

	clientTLS := clientCfg.TLSConfig().Clone()
	clientTLS.ServerName = serverName
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{},
		Config:    clientTLS,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, clientErr := dialer.DialContext(ctx, "tcp", listener.Addr().String())
	if clientErr == nil {
		clientErr = conn.(*tls.Conn).Handshake()
		conn.Close()
	}

	var serverErr error
	select {
	case serverErr = <-serverDone:
	case <-time.After(2 * time.Second):
		return errors.New("server handshake timeout")
	}

	if clientErr != nil {
		return clientErr
	}

	return serverErr
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
