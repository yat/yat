package yat_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"yat.io/yat"
)

func TestClientServer_SPIFFERules_realTLS(t *testing.T) {
	ca, caKey, roots := newAuthTestCA(t)
	serverCert := newAuthTestLeaf(t, ca, caKey, authLeafSpec{
		commonName: "server",
		dnsNames:   []string{"localhost"},
		extUsage:   x509.ExtKeyUsageServerAuth,
	})
	allowedCert := newAuthTestLeaf(t, ca, caKey, authLeafSpec{
		commonName: "allowed",
		uris:       []string{"spiffe://example.org/svc/api"},
		extUsage:   x509.ExtKeyUsageClientAuth,
	})

	tcs := []struct {
		name    string
		uris    []string
		wantSub bool
		wantPub bool
	}{
		{
			name:    "matching spiffe id",
			uris:    []string{"spiffe://example.org/svc/api"},
			wantSub: true,
			wantPub: true,
		},
		{
			name: "domain mismatch",
			uris: []string{"spiffe://other.org/svc/api"},
		},
		{
			name: "path mismatch",
			uris: []string{"spiffe://example.org/svc/other"},
		},
		{
			name: "no uri san",
		},
		{
			name: "userinfo rejected",
			uris: []string{"spiffe://user@example.org/svc/api"},
		},
		{
			name: "query rejected",
			uris: []string{"spiffe://example.org/svc/api?x=1"},
		},
		{
			name: "force query rejected",
			uris: []string{"spiffe://example.org/svc/api?"},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			rs, err := yat.NewRuleSet([]yat.Rule{
				{
					Grants: []yat.Grant{{
						Path:    yat.NewPath("ready/**"),
						Actions: []yat.Action{yat.ActionPub, yat.ActionSub},
					}},
				},
				{
					SPIFFE: &yat.SPIFFESpec{
						Domain: "example.org",
						Path:   yat.NewPath("svc/api"),
					},
					Grants: []yat.Grant{{
						Path:    yat.NewPath("private/**"),
						Actions: []yat.Action{yat.ActionPub, yat.ActionSub},
					}},
				},
			})
			if err != nil {
				t.Fatal(err)
			}

			addr := startAuthTLSServer(t, rs, serverCert, roots)
			watcher := newAuthTLSClient(t, addr, roots, allowedCert)
			publisher := newAuthTLSClient(t, addr, roots, allowedCert)
			caseCert := newAuthTestLeaf(t, ca, caKey, authLeafSpec{
				commonName: "case",
				uris:       tc.uris,
				extUsage:   x509.ExtKeyUsageClientAuth,
			})
			client := newAuthTLSClient(t, addr, roots, caseCert)

			waitClientReady(t, watcher, "tls-watch-"+tc.name)
			waitClientReady(t, publisher, "tls-pub-"+tc.name)
			waitClientReady(t, client, "tls-case-"+tc.name)

			watchC, unsubWatch := mustSubscribeClient(t, watcher, "private/topic")
			t.Cleanup(unsubWatch)
			caseC, unsubCase := mustSubscribeClient(t, client, "private/topic")
			t.Cleanup(unsubCase)
			waitClientReady(t, watcher, "tls-watch-sub-"+tc.name)
			waitClientReady(t, client, "tls-case-sub-"+tc.name)

			if err := publisher.Publish(yat.Msg{
				Path: yat.NewPath("private/topic"),
				Data: []byte("from-allowed"),
			}); err != nil {
				t.Fatal(err)
			}

			assertClientMsg(t, mustRecvClientMsg(t, watchC), "private/topic", []byte("from-allowed"), "")
			if tc.wantSub {
				assertClientMsg(t, mustRecvClientMsg(t, caseC), "private/topic", []byte("from-allowed"), "")
			} else {
				mustNoClientMsg(t, caseC)
			}

			if err := client.Publish(yat.Msg{
				Path: yat.NewPath("private/topic"),
				Data: []byte("from-case"),
			}); err != nil {
				t.Fatal(err)
			}

			if tc.wantPub {
				assertClientMsg(t, mustRecvClientMsg(t, watchC), "private/topic", []byte("from-case"), "")
			} else {
				mustNoClientMsg(t, watchC)
			}
		})
	}
}

func TestClientServer_SPIFFEDomainOnly_realTLS(t *testing.T) {
	ca, caKey, roots := newAuthTestCA(t)
	serverCert := newAuthTestLeaf(t, ca, caKey, authLeafSpec{
		commonName: "server",
		dnsNames:   []string{"localhost"},
		extUsage:   x509.ExtKeyUsageServerAuth,
	})
	pathlessCert := newAuthTestLeaf(t, ca, caKey, authLeafSpec{
		commonName: "pathless",
		uris:       []string{"spiffe://example.org"},
		extUsage:   x509.ExtKeyUsageClientAuth,
	})

	rs, err := yat.NewRuleSet([]yat.Rule{
		{
			Grants: []yat.Grant{{
				Path:    yat.NewPath("ready/**"),
				Actions: []yat.Action{yat.ActionPub, yat.ActionSub},
			}},
		},
		{
			SPIFFE: &yat.SPIFFESpec{Domain: "example.org"},
			Grants: []yat.Grant{{
				Path:    yat.NewPath("private/**"),
				Actions: []yat.Action{yat.ActionPub, yat.ActionSub},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	addr := startAuthTLSServer(t, rs, serverCert, roots)
	watcher := newAuthTLSClient(t, addr, roots, pathlessCert)
	client := newAuthTLSClient(t, addr, roots, pathlessCert)

	waitClientReady(t, watcher, "tls-domain-watch")
	waitClientReady(t, client, "tls-domain-case")

	watchC, unsubWatch := mustSubscribeClient(t, watcher, "private/domain")
	t.Cleanup(unsubWatch)
	caseC, unsubCase := mustSubscribeClient(t, client, "private/domain")
	t.Cleanup(unsubCase)
	waitClientReady(t, watcher, "tls-domain-watch-sub")
	waitClientReady(t, client, "tls-domain-case-sub")

	if err := client.Publish(yat.Msg{
		Path: yat.NewPath("private/domain"),
		Data: []byte("pathless"),
	}); err != nil {
		t.Fatal(err)
	}

	assertClientMsg(t, mustRecvClientMsg(t, watchC), "private/domain", []byte("pathless"), "")
	assertClientMsg(t, mustRecvClientMsg(t, caseC), "private/domain", []byte("pathless"), "")
}

type authLeafSpec struct {
	commonName string
	dnsNames   []string
	uris       []string
	extUsage   x509.ExtKeyUsage
}

var authSerial atomic.Uint64

func newAuthTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().Add(-time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(int64(authSerial.Add(1))),
		Subject: pkix.Name{
			CommonName: "auth test ca",
		},
		NotBefore:             now,
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}

	crt, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(crt)

	return crt, key, pool
}

func newAuthTestLeaf(t *testing.T, parent *x509.Certificate, signer *ecdsa.PrivateKey, spec authLeafSpec) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var uris []*url.URL
	for _, raw := range spec.uris {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		uris = append(uris, u)
	}

	now := time.Now().Add(-time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(int64(authSerial.Add(1))),
		Subject: pkix.Name{
			CommonName: spec.commonName,
		},
		NotBefore:             now,
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{spec.extUsage},
		BasicConstraintsValid: true,
		DNSNames:              spec.dnsNames,
		URIs:                  uris,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}

	crt, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        crt,
	}
}

func startAuthTLSServer(t *testing.T, rules *yat.RuleSet, cert tls.Certificate, roots *x509.CertPool) string {
	t.Helper()

	srv, err := yat.NewServer(yat.NewRouter(), yat.ServerConfig{
		Rules: rules,
	})
	if err != nil {
		t.Fatal(err)
	}

	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    roots,
	})
	if err != nil {
		t.Fatal(err)
	}

	serveC := make(chan error, 1)
	go func() {
		serveC <- srv.Serve(l)
	}()

	t.Cleanup(func() {
		_ = l.Close()
		err := <-serveC
		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("serve: %v", err)
		}
	})

	return l.Addr().String()
}

func newAuthTLSClient(t *testing.T, addr string, roots *x509.CertPool, cert tls.Certificate) *yat.Client {
	t.Helper()

	dialer := tls.Dialer{
		Config: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			ServerName:   "localhost",
			RootCAs:      roots,
			Certificates: []tls.Certificate{cert},
		},
	}

	c, err := yat.NewClient(func(ctx context.Context) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp", addr)
	}, yat.ClientConfig{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = c.Close()
	})

	return c
}
