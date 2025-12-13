package yat_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"testing"

	"golang.org/x/net/http2"
	"yat.io/yat"
	"yat.io/yat/internal/pkigen"
)

func TestServer(t *testing.T) {
	rootCrt, rootKey, err := pkigen.NewRoot()
	if err != nil {
		t.Fatal(err)
	}

	localhost := net.ParseIP("127.0.0.1")
	svrCrt, svrKey, err := pkigen.NewLeaf(rootCrt, rootKey, pkigen.IP(localhost))
	if err != nil {
		t.Fatal(err)
	}

	svrTLSConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{svrCrt.Raw},
				PrivateKey:  svrKey,
				Leaf:        svrCrt,
			},
		},
	}

	clientTLSConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    x509.NewCertPool(),
		NextProtos: []string{"y0"},
	}

	clientTLSConfig.RootCAs.AddCert(rootCrt)

	t.Run("flush", func(t *testing.T) {
		svr, err := yat.NewServer(svrTLSConfig, yat.ServerConfig{})
		if err != nil {
			t.Fatal(err)
		}

		l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: localhost})
		if err != nil {
			t.Fatal(err)
		}

		go func() {
			err := svr.Serve(l)
			t.Logf("serve: %v", err)
		}()

		conn, err := tls.Dial("tcp", l.Addr().String(), clientTLSConfig)
		if err != nil {
			t.Fatal(err)
		}

		yc := yat.NewConn(conn)
		defer yc.Close()

		if err := yc.Flush(t.Context()); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("http", func(t *testing.T) {
		svr, err := yat.NewServer(svrTLSConfig, yat.ServerConfig{})
		if err != nil {
			t.Fatal(err)
		}

		l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: localhost})
		if err != nil {
			t.Fatal(err)
		}

		go func() {
			err := svr.Serve(l)
			t.Logf("serve: %v", err)
		}()

		hc := &http.Client{
			Transport: &http2.Transport{
				TLSClientConfig: clientTLSConfig,
			},
		}

		url := fmt.Sprintf("https://%v", l.Addr())
		res, err := hc.Get(url)
		if err != nil {
			t.Fatal(err)
		}

		if want, got := 200, res.StatusCode; got != want {
			t.Errorf("GET %s: status %d != %d", url, got, want)
		}
	})
}
