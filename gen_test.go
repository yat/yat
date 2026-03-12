//go:build !human

package yat_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"yat.io/yat"
	"yat.io/yat/pkigen"
)

func TestGroup_NewGroup(t *testing.T) {
	const name = "name"
	g := yat.NewGroup(name)
	g1 := yat.NewGroup(name)
	o := yat.NewGroup("other")

	if got, want := g.String(), name; got != want {
		t.Errorf("%q != %q", got, want)
	}

	if g1 != g {
		t.Errorf("%#v != %#v", g1, g)
	}
	if o == g {
		t.Errorf("%#v == %#v", o, g)
	}

	if empty, zero := yat.NewGroup(""), (yat.Group{}); empty != zero {
		t.Errorf("%#v != %#v", empty, zero)
	}

	if s := yat.NewGroup("").String(); s != "" {
		t.Errorf("empty group string %q != %q", s, "")
	}

	if s := yat.NewGroup(strings.Repeat("x", yat.MaxGroupLen)).String(); len(s) != yat.MaxGroupLen {
		t.Fatalf("len(s): %d != %d", len(s), yat.MaxGroupLen)
	}

	defer func() {
		if recover() == nil {
			t.Fatal("no panic")
		}
	}()

	yat.NewGroup(strings.Repeat("x", yat.MaxGroupLen+1))
}

func TestRouter_GroupedRoutingCandidates(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rr := yat.NewRouter()

		var (
			g1a atomic.Uint64
			g1b atomic.Uint64
			g2a atomic.Uint64
			g2b atomic.Uint64

			lit  atomic.Uint64
			wild atomic.Uint64
			all  atomic.Uint64
		)

		type subCase struct {
			sel     yat.Sel
			counter *atomic.Uint64
		}

		selectorCases := []subCase{
			{sel: yat.Sel{Path: yat.NewPath("a/b"), Group: yat.NewGroup("g1")}, counter: &g1a},
			{sel: yat.Sel{Path: yat.NewPath("a/*"), Group: yat.NewGroup("g1")}, counter: &g1b},
			{sel: yat.Sel{Path: yat.NewPath("a/b"), Group: yat.NewGroup("g2")}, counter: &g2a},
			{sel: yat.Sel{Path: yat.NewPath("a/*"), Group: yat.NewGroup("g2")}, counter: &g2b},
			{sel: yat.Sel{Path: yat.NewPath("a/b")}, counter: &lit},
			{sel: yat.Sel{Path: yat.NewPath("a/*")}, counter: &wild},
			{sel: yat.Sel{Path: yat.NewPath("**")}, counter: &all},
		}

		var subs []yat.Sub
		for _, tc := range selectorCases {
			tc := tc
			sub, err := rr.Subscribe(tc.sel, func(yat.Msg) {
				tc.counter.Add(1)
			})
			if err != nil {
				t.Fatalf("subscribe %q: %v", tc.sel.Path.String(), err)
			}
			subs = append(subs, sub)
		}
		t.Cleanup(func() {
			for _, sub := range subs {
				sub.Cancel()
			}
		})

		const npub = 200
		for range npub {
			if err := rr.Publish(yat.Msg{Path: yat.NewPath("a/b")}); err != nil {
				t.Fatal(err)
			}
		}

		synctest.Wait()

		if got := g1a.Load() + g1b.Load(); got != npub {
			t.Fatalf("group g1 deliveries: %d != %d", got, npub)
		}
		if got := g2a.Load() + g2b.Load(); got != npub {
			t.Fatalf("group g2 deliveries: %d != %d", got, npub)
		}

		if got := lit.Load(); got != npub {
			t.Fatalf("literal deliveries: %d != %d", got, npub)
		}
		if got := wild.Load(); got != npub {
			t.Fatalf("wildcard deliveries: %d != %d", got, npub)
		}
		if got := all.Load(); got != npub {
			t.Fatalf("match-all deliveries: %d != %d", got, npub)
		}
	})
}

func TestNewRuleSet(t *testing.T) {
	t.Run("valid rules", func(t *testing.T) {
		_, err := yat.NewRuleSet([]yat.Rule{
			{
				Grants: []yat.Grant{{
					Path:    yat.NewPath("a/**"),
					Actions: []yat.Action{yat.ActionSub},
				}},
			},
			{
				SPIFFE: &yat.SPIFFESpec{
					Domain: "trust-domain",
					Path:   yat.NewPath("a/*"),
				},
				Grants: []yat.Grant{{
					Path:    yat.NewPath("b/**"),
					Actions: []yat.Action{yat.ActionPub, yat.ActionSub},
				}},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
	})

	tcs := []struct {
		name  string
		rules []yat.Rule
	}{
		{
			name: "empty spiffe domain",
			rules: []yat.Rule{{
				SPIFFE: &yat.SPIFFESpec{},
				Grants: []yat.Grant{{
					Path:    yat.NewPath("path"),
					Actions: []yat.Action{yat.ActionPub},
				}},
			}},
		},
		{
			name: "invalid spiffe domain",
			rules: []yat.Rule{{
				SPIFFE: &yat.SPIFFESpec{Domain: "Trust-Domain"},
				Grants: []yat.Grant{{
					Path:    yat.NewPath("path"),
					Actions: []yat.Action{yat.ActionPub},
				}},
			}},
		},
		{
			name:  "empty grants",
			rules: []yat.Rule{{}},
		},
		{
			name: "empty grant path",
			rules: []yat.Rule{{
				Grants: []yat.Grant{{
					Actions: []yat.Action{yat.ActionPub},
				}},
			}},
		},
		{
			name: "empty grant actions",
			rules: []yat.Rule{{
				Grants: []yat.Grant{{
					Path: yat.NewPath("path"),
				}},
			}},
		},
		{
			name: "invalid grant action",
			rules: []yat.Rule{{
				Grants: []yat.Grant{{
					Path:    yat.NewPath("path"),
					Actions: []yat.Action{"delete"},
				}},
			}},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := yat.NewRuleSet(tc.rules); err == nil {
				t.Fatal("no error")
			}
		})
	}
}

func TestRuleSetCompile(t *testing.T) {
	ca, caKey, err := pkigen.NewRoot(pkigen.CN("rule-set-root"))
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca)

	serverLeaf, serverKey, err := pkigen.NewLeaf(ca, caKey, pkigen.CN("rule-set-server"), pkigen.DNS("localhost"))
	if err != nil {
		t.Fatal(err)
	}
	serverCert := tls.Certificate{
		Certificate: [][]byte{serverLeaf.Raw},
		PrivateKey:  serverKey,
		Leaf:        serverLeaf,
	}

	allowedLeaf, allowedKey, err := pkigen.NewLeaf(ca, caKey, pkigen.CN("rule-set-allowed"), pkigen.URI("spiffe://trust-domain/a/b"))
	if err != nil {
		t.Fatal(err)
	}
	allowedCert := tls.Certificate{
		Certificate: [][]byte{allowedLeaf.Raw},
		PrivateKey:  allowedKey,
		Leaf:        allowedLeaf,
	}

	otherLeaf, otherKey, err := pkigen.NewLeaf(ca, caKey, pkigen.CN("rule-set-other"), pkigen.URI("spiffe://other-domain/a/b"))
	if err != nil {
		t.Fatal(err)
	}
	otherCert := tls.Certificate{
		Certificate: [][]byte{otherLeaf.Raw},
		PrivateKey:  otherKey,
		Leaf:        otherLeaf,
	}

	rs, err := yat.NewRuleSet([]yat.Rule{
		{
			Grants: []yat.Grant{{
				Path:    yat.NewPath("a/**"),
				Actions: []yat.Action{yat.ActionSub},
			}},
		},
		{
			SPIFFE: &yat.SPIFFESpec{Domain: "trust-domain"},
			Grants: []yat.Grant{{
				Path:    yat.NewPath("b/**"),
				Actions: []yat.Action{yat.ActionSub},
			}},
		},
		{
			SPIFFE: &yat.SPIFFESpec{
				Domain: "trust-domain",
				Path:   yat.NewPath("a/*"),
			},
			Grants: []yat.Grant{{
				Path:    yat.NewPath("c/**"),
				Actions: []yat.Action{yat.ActionPub},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	anon := rs.Compile(yat.Principal{})
	if !anon(yat.NewPath("a/b"), yat.ActionSub) {
		t.Fatal("anonymous access denied")
	}
	if anon(yat.NewPath("b/b"), yat.ActionSub) {
		t.Fatal("anonymous spiffe grant allowed")
	}

	authd := rs.Compile(yat.Principal{
		Conn: newAuthTLSPrincipalConn(t, roots, serverCert, allowedCert),
	})
	if !authd(yat.NewPath("a/b"), yat.ActionSub) {
		t.Fatal("authenticated access denied")
	}
	if !authd(yat.NewPath("b/b"), yat.ActionSub) {
		t.Fatal("domain grant denied")
	}
	if !authd(yat.NewPath("c/b"), yat.ActionPub) {
		t.Fatal("path grant denied")
	}
	if authd(yat.NewPath("c/b"), yat.ActionSub) {
		t.Fatal("unexpected sub grant")
	}

	other := rs.Compile(yat.Principal{
		Conn: newAuthTLSPrincipalConn(t, roots, serverCert, otherCert),
	})
	if other(yat.NewPath("b/b"), yat.ActionSub) {
		t.Fatal("unexpected other-domain grant")
	}
}

func TestAllowAll(t *testing.T) {
	allow := yat.AllowAll().Compile(yat.Principal{})

	if !allow(yat.NewPath("a"), yat.ActionPub) {
		t.Fatal("pub denied")
	}
	if !allow(yat.NewPath("b"), yat.ActionSub) {
		t.Fatal("sub denied")
	}
}

func newAuthTLSPrincipalConn(t *testing.T, roots *x509.CertPool, serverCert tls.Certificate, clientCert tls.Certificate) net.Conn {
	t.Helper()

	serverRaw, clientRaw := net.Pipe()
	serverTLS := tls.Server(serverRaw, &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    roots,
	})
	clientTLS := tls.Client(clientRaw, &tls.Config{
		MinVersion:   tls.VersionTLS13,
		ServerName:   "localhost",
		RootCAs:      roots,
		Certificates: []tls.Certificate{clientCert},
	})

	errC := make(chan error, 2)
	go func() {
		errC <- serverTLS.Handshake()
	}()
	go func() {
		errC <- clientTLS.Handshake()
	}()

	for i := 0; i < 2; i++ {
		if err := <-errC; err != nil {
			t.Fatal(err)
		}
	}

	// We only need the verified connection state for auth checks. Closing the raw
	// ends avoids slow TLS close-notify behavior on net.Pipe during test cleanup.
	_ = serverRaw.Close()
	_ = clientRaw.Close()

	return serverTLS
}

func TestClientServer_SPIFFERules_realTLS(t *testing.T) {
	ca, caKey, err := pkigen.NewRoot(pkigen.CN("auth-root"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)

	serverLeaf, serverKey, err := pkigen.NewLeaf(ca, caKey, pkigen.CN("server"), pkigen.DNS("localhost"))
	if err != nil {
		t.Fatal(err)
	}
	serverCert := tls.Certificate{
		Certificate: [][]byte{serverLeaf.Raw},
		PrivateKey:  serverKey,
		Leaf:        serverLeaf,
	}

	allowedLeaf, allowedKey, err := pkigen.NewLeaf(ca, caKey, pkigen.CN("allowed"), pkigen.URI("spiffe://trust-domain/a/b"))
	if err != nil {
		t.Fatal(err)
	}
	allowedCert := tls.Certificate{
		Certificate: [][]byte{allowedLeaf.Raw},
		PrivateKey:  allowedKey,
		Leaf:        allowedLeaf,
	}

	tcs := []struct {
		name    string
		uris    []string
		wantSub bool
		wantPub bool
	}{
		{
			name:    "matching spiffe id",
			uris:    []string{"spiffe://trust-domain/a/b"},
			wantSub: true,
			wantPub: true,
		},
		{
			name: "domain mismatch",
			uris: []string{"spiffe://other-domain/a/b"},
		},
		{
			name: "path mismatch",
			uris: []string{"spiffe://trust-domain/a/c"},
		},
		{
			name: "no uri san",
		},
		{
			name: "userinfo rejected",
			uris: []string{"spiffe://user@trust-domain/a/b"},
		},
		{
			name: "query rejected",
			uris: []string{"spiffe://trust-domain/a/b?x=1"},
		},
		{
			name: "force query rejected",
			uris: []string{"spiffe://trust-domain/a/b?"},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			rs, err := yat.NewRuleSet([]yat.Rule{
				{
					Grants: []yat.Grant{{
						Path:    yat.NewPath("a/**"),
						Actions: []yat.Action{yat.ActionPub, yat.ActionSub},
					}},
				},
				{
					SPIFFE: &yat.SPIFFESpec{
						Domain: "trust-domain",
						Path:   yat.NewPath("a/b"),
					},
					Grants: []yat.Grant{{
						Path:    yat.NewPath("b/**"),
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
			opts := []pkigen.CertOpt{pkigen.CN("case")}
			for _, uri := range tc.uris {
				opts = append(opts, pkigen.URI(uri))
			}
			caseLeaf, caseKey, err := pkigen.NewLeaf(ca, caKey, opts...)
			if err != nil {
				t.Fatal(err)
			}
			caseCert := tls.Certificate{
				Certificate: [][]byte{caseLeaf.Raw},
				PrivateKey:  caseKey,
				Leaf:        caseLeaf,
			}
			client := newAuthTLSClient(t, addr, roots, caseCert)

			waitClientReady(t, watcher, "tls-watch-"+tc.name)
			waitClientReady(t, publisher, "tls-pub-"+tc.name)
			waitClientReady(t, client, "tls-case-"+tc.name)

			watchC, unsubWatch := mustSubscribeClient(t, watcher, "b/a")
			t.Cleanup(unsubWatch)
			caseC, unsubCase := mustSubscribeClient(t, client, "b/a")
			t.Cleanup(unsubCase)
			waitClientReady(t, watcher, "tls-watch-sub-"+tc.name)
			waitClientReady(t, client, "tls-case-sub-"+tc.name)

			if err := publisher.Publish(yat.Msg{
				Path: yat.NewPath("b/a"),
				Data: []byte("from-allowed"),
			}); err != nil {
				t.Fatal(err)
			}

			assertClientMsg(t, mustRecvClientMsg(t, watchC), "b/a", []byte("from-allowed"), "")
			if tc.wantSub {
				assertClientMsg(t, mustRecvClientMsg(t, caseC), "b/a", []byte("from-allowed"), "")
			} else {
				mustNoClientMsg(t, caseC)
			}

			if err := client.Publish(yat.Msg{
				Path: yat.NewPath("b/a"),
				Data: []byte("from-case"),
			}); err != nil {
				t.Fatal(err)
			}

			if tc.wantPub {
				assertClientMsg(t, mustRecvClientMsg(t, watchC), "b/a", []byte("from-case"), "")
			} else {
				mustNoClientMsg(t, watchC)
			}
		})
	}
}

func TestClientServer_SPIFFEDomainOnly_realTLS(t *testing.T) {
	ca, caKey, err := pkigen.NewRoot(pkigen.CN("auth-root"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)

	serverLeaf, serverKey, err := pkigen.NewLeaf(ca, caKey, pkigen.CN("server"), pkigen.DNS("localhost"))
	if err != nil {
		t.Fatal(err)
	}
	serverCert := tls.Certificate{
		Certificate: [][]byte{serverLeaf.Raw},
		PrivateKey:  serverKey,
		Leaf:        serverLeaf,
	}

	pathlessLeaf, pathlessKey, err := pkigen.NewLeaf(ca, caKey, pkigen.CN("pathless"), pkigen.URI("spiffe://trust-domain"))
	if err != nil {
		t.Fatal(err)
	}
	pathlessCert := tls.Certificate{
		Certificate: [][]byte{pathlessLeaf.Raw},
		PrivateKey:  pathlessKey,
		Leaf:        pathlessLeaf,
	}

	rs, err := yat.NewRuleSet([]yat.Rule{
		{
			Grants: []yat.Grant{{
				Path:    yat.NewPath("a/**"),
				Actions: []yat.Action{yat.ActionPub, yat.ActionSub},
			}},
		},
		{
			SPIFFE: &yat.SPIFFESpec{Domain: "trust-domain"},
			Grants: []yat.Grant{{
				Path:    yat.NewPath("b/**"),
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

	watchC, unsubWatch := mustSubscribeClient(t, watcher, "b/a")
	t.Cleanup(unsubWatch)
	caseC, unsubCase := mustSubscribeClient(t, client, "b/a")
	t.Cleanup(unsubCase)
	waitClientReady(t, watcher, "tls-domain-watch-sub")
	waitClientReady(t, client, "tls-domain-case-sub")

	if err := client.Publish(yat.Msg{
		Path: yat.NewPath("b/a"),
		Data: []byte("pathless"),
	}); err != nil {
		t.Fatal(err)
	}

	assertClientMsg(t, mustRecvClientMsg(t, watchC), "b/a", []byte("pathless"), "")
	assertClientMsg(t, mustRecvClientMsg(t, caseC), "b/a", []byte("pathless"), "")
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

const (
	msgTimeout   = 2 * time.Second
	noMsgTimeout = 150 * time.Millisecond
)

func TestClientServer_SameClient(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, l := startTestServer(t)
		c := newYatClient(t, l)

		msgC, unsub := mustSubscribeClient(t, c, "path")
		t.Cleanup(unsub)
		waitClientReady(t, c, "same")

		if err := c.Publish(yat.Msg{
			Path:  yat.NewPath("path"),
			Data:  []byte("first"),
			Inbox: yat.NewPath("inbox"),
		}); err != nil {
			t.Fatal(err)
		}

		got := mustRecvClientMsg(t, msgC)
		assertClientMsg(t, got, "path", []byte("first"), "inbox")

		if err := c.Publish(yat.Msg{
			Path: yat.NewPath("b"),
			Data: []byte("stale"),
		}); err != nil {
			t.Fatal(err)
		}
		mustNoClientMsg(t, msgC)

		unsub()
		if err := c.Publish(yat.Msg{
			Path: yat.NewPath("path"),
			Data: []byte("gone"),
		}); err != nil {
			t.Fatal(err)
		}
		mustNoClientMsg(t, msgC)
	})
}

func TestClientServer_MultipleClientsSameServer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, l := startTestServer(t)

		sub1 := newYatClient(t, l)
		sub2 := newYatClient(t, l)
		nomatch := newYatClient(t, l)
		pub1 := newYatClient(t, l)
		pub2 := newYatClient(t, l)

		waitClientReady(t, sub1, "same-s1")
		waitClientReady(t, sub2, "same-s2")
		waitClientReady(t, nomatch, "same-nomatch")
		waitClientReady(t, pub1, "same-p1")
		waitClientReady(t, pub2, "same-p2")

		sub1C, unsub1 := mustSubscribeClient(t, sub1, "a")
		sub2C, unsub2 := mustSubscribeClient(t, sub2, "a")
		negC, unsubNeg := mustSubscribeClient(t, nomatch, "b")
		t.Cleanup(unsub1)
		t.Cleanup(unsub2)
		t.Cleanup(unsubNeg)
		waitClientReady(t, sub1, "same-s1-sub")
		waitClientReady(t, sub2, "same-s2-sub")
		waitClientReady(t, nomatch, "same-neg-sub")

		if err := pub1.Publish(yat.Msg{
			Path: yat.NewPath("a"),
			Data: []byte("fanout-1"),
		}); err != nil {
			t.Fatal(err)
		}

		if err := pub2.Publish(yat.Msg{
			Path: yat.NewPath("a"),
			Data: []byte("fanout-2"),
		}); err != nil {
			t.Fatal(err)
		}

		got11 := mustRecvClientMsg(t, sub1C)
		got12 := mustRecvClientMsg(t, sub1C)
		got21 := mustRecvClientMsg(t, sub2C)
		got22 := mustRecvClientMsg(t, sub2C)

		for _, got := range []yat.Msg{got11, got12, got21, got22} {
			if got.Path.String() != "a" {
				t.Fatalf("path: %q != %q", got.Path.String(), "a")
			}
		}

		sub1Seen := map[string]bool{
			string(got11.Data): true,
			string(got12.Data): true,
		}
		if !sub1Seen["fanout-1"] || !sub1Seen["fanout-2"] {
			t.Fatalf("sub1 data: %q, %q", got11.Data, got12.Data)
		}

		sub2Seen := map[string]bool{
			string(got21.Data): true,
			string(got22.Data): true,
		}
		if !sub2Seen["fanout-1"] || !sub2Seen["fanout-2"] {
			t.Fatalf("sub2 data: %q, %q", got21.Data, got22.Data)
		}

		mustNoClientMsg(t, negC)
	})
}

func TestClientServer_RouterAndClients(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rr, l := startTestServer(t)

		sub1 := newYatClient(t, l)
		sub2 := newYatClient(t, l)
		pub := newYatClient(t, l)

		waitClientReady(t, sub1, "router-s1")
		waitClientReady(t, sub2, "router-s2")
		waitClientReady(t, pub, "router-pub")

		sub1C, unsub1 := mustSubscribeClient(t, sub1, "a")
		sub2C, unsub2 := mustSubscribeClient(t, sub2, "a")
		t.Cleanup(unsub1)
		t.Cleanup(unsub2)
		waitClientReady(t, sub1, "router-s1-sub")
		waitClientReady(t, sub2, "router-s2-sub")

		if err := rr.Publish(yat.Msg{
			Path:  yat.NewPath("a"),
			Data:  []byte("from-router"),
			Inbox: yat.NewPath("inbox"),
		}); err != nil {
			t.Fatal(err)
		}

		got1 := mustRecvClientMsg(t, sub1C)
		got2 := mustRecvClientMsg(t, sub2C)
		assertClientMsg(t, got1, "a", []byte("from-router"), "inbox")
		assertClientMsg(t, got2, "a", []byte("from-router"), "inbox")

		routerSub1 := make(chan yat.Msg, 8)
		routerSub2 := make(chan yat.Msg, 8)
		subR1, err := rr.Subscribe(yat.Sel{Path: yat.NewPath("b")}, func(m yat.Msg) {
			routerSub1 <- cloneMsg(m)
		})
		if err != nil {
			t.Fatal(err)
		}
		subR2, err := rr.Subscribe(yat.Sel{Path: yat.NewPath("b")}, func(m yat.Msg) {
			routerSub2 <- cloneMsg(m)
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(subR1.Cancel)
		t.Cleanup(subR2.Cancel)

		if err := pub.Publish(yat.Msg{
			Path:  yat.NewPath("b"),
			Data:  []byte("from-client"),
			Inbox: yat.NewPath("inbox"),
		}); err != nil {
			t.Fatal(err)
		}

		assertClientMsg(t, mustRecvClientMsg(t, routerSub1), "b", []byte("from-client"), "inbox")
		assertClientMsg(t, mustRecvClientMsg(t, routerSub2), "b", []byte("from-client"), "inbox")
	})
}

func TestClientServer_GroupedRoutingCandidates(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, l := startTestServer(t)

		g1a := newYatClient(t, l)
		g1b := newYatClient(t, l)
		g2a := newYatClient(t, l)
		g2b := newYatClient(t, l)
		lit := newYatClient(t, l)
		w1 := newYatClient(t, l)
		w2 := newYatClient(t, l)
		pub := newYatClient(t, l)

		waitClientReady(t, g1a, "group-g1a")
		waitClientReady(t, g1b, "group-g1b")
		waitClientReady(t, g2a, "group-g2a")
		waitClientReady(t, g2b, "group-g2b")
		waitClientReady(t, lit, "group-lit")
		waitClientReady(t, w1, "group-w1")
		waitClientReady(t, w2, "group-w2")
		waitClientReady(t, pub, "group-pub")

		g1aC, unsubG1A := mustSubscribeClientSel(t, g1a, yat.Sel{
			Path:  yat.NewPath("topic/a/b"),
			Group: yat.NewGroup("g1"),
		})
		g1bC, unsubG1B := mustSubscribeClientSel(t, g1b, yat.Sel{
			Path:  yat.NewPath("topic/a/*"),
			Group: yat.NewGroup("g1"),
		})
		g2aC, unsubG2A := mustSubscribeClientSel(t, g2a, yat.Sel{
			Path:  yat.NewPath("topic/a/b"),
			Group: yat.NewGroup("g2"),
		})
		g2bC, unsubG2B := mustSubscribeClientSel(t, g2b, yat.Sel{
			Path:  yat.NewPath("topic/*/b"),
			Group: yat.NewGroup("g2"),
		})
		litC, unsubLit := mustSubscribeClientSel(t, lit, yat.Sel{Path: yat.NewPath("topic/a/b")})
		w1C, unsubW1 := mustSubscribeClientSel(t, w1, yat.Sel{Path: yat.NewPath("topic/a/*")})
		w2C, unsubW2 := mustSubscribeClientSel(t, w2, yat.Sel{Path: yat.NewPath("topic/*/b")})
		t.Cleanup(unsubG1A)
		t.Cleanup(unsubG1B)
		t.Cleanup(unsubG2A)
		t.Cleanup(unsubG2B)
		t.Cleanup(unsubLit)
		t.Cleanup(unsubW1)
		t.Cleanup(unsubW2)

		waitClientReady(t, g1a, "group-g1a-sub")
		waitClientReady(t, g1b, "group-g1b-sub")
		waitClientReady(t, g2a, "group-g2a-sub")
		waitClientReady(t, g2b, "group-g2b-sub")
		waitClientReady(t, lit, "group-lit-sub")
		waitClientReady(t, w1, "group-w1-sub")
		waitClientReady(t, w2, "group-w2-sub")

		const npub = 200
		for i := range npub {
			if err := pub.Publish(yat.Msg{
				Path: yat.NewPath("topic/a/b"),
				Data: []byte{byte(i)},
			}); err != nil {
				t.Fatal(err)
			}
		}

		synctest.Wait()

		countMsgs := func(msgC <-chan yat.Msg) (n int) {
			for {
				select {
				case <-msgC:
					n++
				case <-time.After(noMsgTimeout):
					return n
				}
			}
		}

		g1Total := countMsgs(g1aC) + countMsgs(g1bC)
		g2Total := countMsgs(g2aC) + countMsgs(g2bC)
		if g1Total != npub {
			t.Fatalf("g1 deliveries: %d != %d", g1Total, npub)
		}
		if g2Total != npub {
			t.Fatalf("g2 deliveries: %d != %d", g2Total, npub)
		}

		if n := countMsgs(litC); n != npub {
			t.Fatalf("literal deliveries: %d != %d", n, npub)
		}
		if n := countMsgs(w1C); n != npub {
			t.Fatalf("wildcard a/* deliveries: %d != %d", n, npub)
		}
		if n := countMsgs(w2C); n != npub {
			t.Fatalf("wildcard */b deliveries: %d != %d", n, npub)
		}
	})
}

func TestClientServer_MultipleServersSharedRouter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rr := yat.NewRouter()
		l1 := startTestServerWithRouter(t, rr)
		l2 := startTestServerWithRouter(t, rr)

		sub1 := newYatClient(t, l1)
		sub2 := newYatClient(t, l2)
		pub1 := newYatClient(t, l1)
		pub2 := newYatClient(t, l2)

		waitClientReady(t, sub1, "shared-s1")
		waitClientReady(t, sub2, "shared-s2")
		waitClientReady(t, pub1, "shared-p1")
		waitClientReady(t, pub2, "shared-p2")

		sub1C, unsub1 := mustSubscribeClient(t, sub1, "path")
		sub2C, unsub2 := mustSubscribeClient(t, sub2, "path")
		t.Cleanup(unsub1)
		t.Cleanup(unsub2)
		waitClientReady(t, sub1, "shared-s1-sub")
		waitClientReady(t, sub2, "shared-s2-sub")

		if err := pub1.Publish(yat.Msg{
			Path:  yat.NewPath("path"),
			Data:  []byte("from-srv-1"),
			Inbox: yat.NewPath("inbox/a"),
		}); err != nil {
			t.Fatal(err)
		}

		assertClientMsg(t, mustRecvClientMsg(t, sub1C), "path", []byte("from-srv-1"), "inbox/a")
		assertClientMsg(t, mustRecvClientMsg(t, sub2C), "path", []byte("from-srv-1"), "inbox/a")

		if err := pub2.Publish(yat.Msg{
			Path:  yat.NewPath("path"),
			Data:  []byte("from-srv-2"),
			Inbox: yat.NewPath("inbox/b"),
		}); err != nil {
			t.Fatal(err)
		}

		assertClientMsg(t, mustRecvClientMsg(t, sub1C), "path", []byte("from-srv-2"), "inbox/b")
		assertClientMsg(t, mustRecvClientMsg(t, sub2C), "path", []byte("from-srv-2"), "inbox/b")

		if err := rr.Publish(yat.Msg{
			Path:  yat.NewPath("path"),
			Data:  []byte("from-router"),
			Inbox: yat.NewPath("inbox"),
		}); err != nil {
			t.Fatal(err)
		}

		assertClientMsg(t, mustRecvClientMsg(t, sub1C), "path", []byte("from-router"), "inbox")
		assertClientMsg(t, mustRecvClientMsg(t, sub2C), "path", []byte("from-router"), "inbox")
	})
}

func newYatClient(t *testing.T, l *pipeListener) *yat.Client {
	t.Helper()

	c, err := yat.NewClient(func(context.Context) (net.Conn, error) {
		return l.Dial()
	}, yat.ClientConfig{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = c.Close()
	})

	return c
}

type pipeListener struct {
	connC chan net.Conn
	doneC chan struct{}
	once  sync.Once
}

type pipeAddr struct{}

func newPipeListener() *pipeListener {
	return &pipeListener{
		connC: make(chan net.Conn, 32),
		doneC: make(chan struct{}),
	}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case <-l.doneC:
		return nil, net.ErrClosed

	case c := <-l.connC:
		return c, nil
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() {
		close(l.doneC)
		for {
			select {
			case c := <-l.connC:
				_ = c.Close()

			default:
				return
			}
		}
	})
	return nil
}

func (l *pipeListener) Addr() net.Addr {
	return pipeAddr{}
}

func (l *pipeListener) Dial() (net.Conn, error) {
	serverConn, clientConn := net.Pipe()
	select {
	case <-l.doneC:
		_ = serverConn.Close()
		_ = clientConn.Close()
		return nil, net.ErrClosed

	case l.connC <- serverConn:
		return clientConn, nil
	}
}

func (pipeAddr) Network() string {
	return "pipe"
}

func (pipeAddr) String() string {
	return "pipe"
}

func startTestServer(t *testing.T) (*yat.Router, *pipeListener) {
	t.Helper()

	rr := yat.NewRouter()
	l := startTestServerWithRouter(t, rr)
	return rr, l
}

func startTestServerWithRouter(t *testing.T, rr *yat.Router) *pipeListener {
	t.Helper()

	return startTestServerWithRules(t, rr, yat.AllowAll())
}

func startTestServerWithRules(t *testing.T, rr *yat.Router, rules *yat.RuleSet) *pipeListener {
	t.Helper()

	srv, err := yat.NewServer(rr, yat.ServerConfig{
		Rules: rules,
	})
	if err != nil {
		t.Fatal(err)
	}

	l := newPipeListener()

	serveC := make(chan error, 1)
	go func() {
		serveC <- srv.Serve(l)
	}()

	t.Cleanup(func() {
		_ = l.Close()
		err := <-serveC
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("serve: %v", err)
		}
	})

	return l
}

func waitClientReady(t *testing.T, c *yat.Client, id string) {
	t.Helper()

	path := "a/" + id
	readyC, unsub := mustSubscribeClient(t, c, path)
	defer unsub()
	if err := c.Publish(yat.Msg{
		Path: yat.NewPath(path),
		Data: []byte("ready"),
	}); err != nil {
		t.Fatal(err)
	}

	got := mustRecvClientMsg(t, readyC)
	assertClientMsg(t, got, path, []byte("ready"), "")
}

func mustSubscribeClient(t *testing.T, c *yat.Client, path string) (<-chan yat.Msg, func()) {
	t.Helper()
	return mustSubscribeClientSel(t, c, yat.Sel{Path: yat.NewPath(path)})
}

func mustSubscribeClientSel(t *testing.T, c *yat.Client, sel yat.Sel) (<-chan yat.Msg, func()) {
	t.Helper()

	msgC := make(chan yat.Msg, 64)
	sub, err := c.Subscribe(sel, func(m yat.Msg) {
		msgC <- cloneMsg(m)
	})
	if err != nil {
		t.Fatal(err)
	}

	return msgC, sub.Cancel
}

func mustRecvClientMsg(t *testing.T, msgC <-chan yat.Msg) yat.Msg {
	t.Helper()

	select {
	case msg := <-msgC:
		return msg

	case <-time.After(msgTimeout):
		t.Fatal("message timeout")
		return yat.Msg{}
	}
}

func mustNoClientMsg(t *testing.T, msgC <-chan yat.Msg) {
	t.Helper()

	select {
	case msg := <-msgC:
		t.Fatalf("unexpected message: path=%q data=%q inbox=%q", msg.Path.String(), msg.Data, msg.Inbox.String())

	case <-time.After(noMsgTimeout):
	}
}

func assertClientMsg(t *testing.T, got yat.Msg, path string, data []byte, inbox string) {
	t.Helper()

	if got.Path.String() != path {
		t.Fatalf("path: %q != %q", got.Path.String(), path)
	}
	if !bytes.Equal(got.Data, data) {
		t.Fatalf("data: %q != %q", got.Data, data)
	}
	if got.Inbox.String() != inbox {
		t.Fatalf("inbox: %q != %q", got.Inbox.String(), inbox)
	}
}

func cloneMsg(m yat.Msg) yat.Msg {
	out := yat.Msg{
		Path: m.Path.Clone(),
		Data: bytes.Clone(m.Data),
	}

	if !m.Inbox.IsZero() {
		out.Inbox = m.Inbox.Clone()
	}

	return out
}
