package yat_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"os"
	"testing"

	"yat.io/yat"
	"yat.io/yat/pkigen"
)

var _ yat.Publisher = (*yat.Client)(nil)
var _ yat.Subscriber = (*yat.Client)(nil)
var _ yat.Caller = (*yat.Client)(nil)

func TestClient(t *testing.T) {
	rootCrt, rootKey, err := pkigen.NewRoot()
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(rootCrt)

	clientCrt, clientKey, err := pkigen.NewLeaf(rootCrt, rootKey)
	if err != nil {
		t.Fatal(err)
	}

	clientTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{Certificate: [][]byte{clientCrt.Raw}, PrivateKey: clientKey, Leaf: clientCrt},
		},

		RootCAs:    roots,
		NextProtos: []string{"yat"},
		MinVersion: tls.VersionTLS13,
		ServerName: "::1",
	}

	svrCrt, svrKey, err := pkigen.NewLeaf(rootCrt, rootKey, pkigen.IP(net.ParseIP("::1")))
	if err != nil {
		t.Fatal(err)
	}

	svrTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{Certificate: [][]byte{svrCrt.Raw}, PrivateKey: svrKey, Leaf: svrCrt},
		},

		NextProtos: []string{"yat"},
		MinVersion: tls.VersionTLS13,

		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  roots,
	}

	bus := &yat.Bus{}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	l, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}

	defer l.Close()

	svr, err := yat.NewServer(bus, svrTLSConfig, yat.ServerConfig{
		Logger:      logger.With("part", "server"),
		DisableAuth: true,
	})

	if err != nil {
		t.Fatal(err)
	}

	go svr.Serve(l)

	dial := func(ctx context.Context) (net.Conn, error) {
		nw := l.Addr().Network()
		addr := l.Addr().String()
		return (&net.Dialer{}).DialContext(ctx, nw, addr)
	}

	client, err := yat.NewClient(dial, clientTLSConfig, yat.ClientConfig{
		Logger: logger.With("part", "client"),
	})

	if err != nil {
		t.Fatal(err)
	}

	err = client.Publish(yat.Msg{
		Topic: yat.Topic("hello"),
	})

	if err != nil {
		t.Fatal(err)
	}

	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}
