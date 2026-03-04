package yat

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/url"
	"testing"
	"time"
)

func TestGrant_allow(t *testing.T) {
	grant := Grant{
		Path:    NewPath("chat/**"),
		Actions: []Action{ActionPub},
	}

	if !grant.allow(NewPath("chat/room"), ActionPub) {
		t.Fatal("no match")
	}
	if grant.allow(NewPath("chat/room"), ActionSub) {
		t.Fatal("unexpected action match")
	}
	if grant.allow(NewPath("other/room"), ActionPub) {
		t.Fatal("unexpected path match")
	}
	if (Grant{}).allow(NewPath("chat/room"), ActionPub) {
		t.Fatal("zero grant matched")
	}
}

func TestSPIFFESpec_match(t *testing.T) {
	tcs := []struct {
		name string
		spec SPIFFESpec
		p    Principal
		want bool
	}{
		{
			name: "nil conn",
			spec: SPIFFESpec{Domain: "example.org"},
			p:    Principal{},
		},
		{
			name: "conn without state",
			spec: SPIFFESpec{Domain: "example.org"},
			p:    Principal{Conn: authNoStateConn{}},
		},
		{
			name: "no verified chains",
			spec: SPIFFESpec{Domain: "example.org"},
			p: Principal{Conn: authStateConn{
				state: tls.ConnectionState{},
			}},
		},
		{
			name: "empty verified chain",
			spec: SPIFFESpec{Domain: "example.org"},
			p: Principal{Conn: authStateConn{
				state: tls.ConnectionState{
					VerifiedChains: [][]*x509.Certificate{{}},
				},
			}},
		},
		{
			name: "no uri sans",
			spec: SPIFFESpec{Domain: "example.org"},
			p:    newAuthPrincipal(),
		},
		{
			name: "multiple uri sans",
			spec: SPIFFESpec{Domain: "example.org"},
			p: newAuthPrincipal(
				mustParseAuthURL(t, "spiffe://example.org/workload"),
				mustParseAuthURL(t, "spiffe://example.org/other"),
			),
		},
		{
			name: "wrong scheme",
			spec: SPIFFESpec{Domain: "example.org"},
			p:    newAuthPrincipal(mustParseAuthURL(t, "https://example.org/workload")),
		},
		{
			name: "query rejected",
			spec: SPIFFESpec{Domain: "example.org"},
			p:    newAuthPrincipal(mustParseAuthURL(t, "spiffe://example.org/workload?a=b")),
		},
		{
			name: "force query rejected",
			spec: SPIFFESpec{Domain: "example.org"},
			p:    newAuthPrincipal(mustParseAuthURL(t, "spiffe://example.org/workload?")),
		},
		{
			name: "userinfo rejected",
			spec: SPIFFESpec{Domain: "example.org"},
			p:    newAuthPrincipal(mustParseAuthURL(t, "spiffe://user@example.org/workload")),
		},
		{
			name: "invalid trust domain rejected",
			spec: SPIFFESpec{Domain: "example.org"},
			p:    newAuthPrincipal(mustParseAuthURL(t, "spiffe://example.org:443/workload")),
		},
		{
			name: "wild path rejected",
			spec: SPIFFESpec{Domain: "example.org"},
			p:    newAuthPrincipal(mustParseAuthURL(t, "spiffe://example.org/*")),
		},
		{
			name: "domain mismatch",
			spec: SPIFFESpec{Domain: "other.org"},
			p:    newAuthPrincipal(mustParseAuthURL(t, "spiffe://example.org/workload")),
		},
		{
			name: "path mismatch",
			spec: SPIFFESpec{Domain: "example.org", Path: NewPath("svc/api")},
			p:    newAuthPrincipal(mustParseAuthURL(t, "spiffe://example.org/svc/web")),
		},
		{
			name: "pathless id matches domain rule",
			spec: SPIFFESpec{Domain: "example.org"},
			p:    newAuthPrincipal(mustParseAuthURL(t, "spiffe://example.org")),
			want: true,
		},
		{
			name: "pathful id matches domain rule",
			spec: SPIFFESpec{Domain: "example.org"},
			p:    newAuthPrincipal(mustParseAuthURL(t, "spiffe://example.org/svc/api")),
			want: true,
		},
		{
			name: "exact path match",
			spec: SPIFFESpec{Domain: "example.org", Path: NewPath("svc/api")},
			p:    newAuthPrincipal(mustParseAuthURL(t, "spiffe://example.org/svc/api")),
			want: true,
		},
		{
			name: "wildcard path match",
			spec: SPIFFESpec{Domain: "example.org", Path: NewPath("svc/*")},
			p:    newAuthPrincipal(mustParseAuthURL(t, "spiffe://example.org/svc/api")),
			want: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.spec.match(tc.p); got != tc.want {
				t.Fatalf("match: %t != %t", got, tc.want)
			}
		})
	}
}

func TestRuleSet_Compile_clonesGrants(t *testing.T) {
	rs := &RuleSet{rr: []Rule{{
		Grants: []Grant{{
			Path:    NewPath("chat/room"),
			Actions: []Action{ActionPub},
		}},
	}}}

	allow := rs.Compile(Principal{})

	rs.rr[0].Grants[0].Path = NewPath("chat/other")
	rs.rr[0].Grants[0].Actions[0] = ActionSub

	if !allow(NewPath("chat/room"), ActionPub) {
		t.Fatal("compiled grant changed")
	}
	if allow(NewPath("chat/other"), ActionPub) {
		t.Fatal("unexpected mutated path grant")
	}
	if allow(NewPath("chat/room"), ActionSub) {
		t.Fatal("unexpected mutated action grant")
	}
}

type authStateConn struct {
	state tls.ConnectionState
}

func (c authStateConn) ConnectionState() tls.ConnectionState { return c.state }
func (authStateConn) Read([]byte) (int, error)               { return 0, io.EOF }
func (authStateConn) Write(p []byte) (int, error)            { return len(p), nil }
func (authStateConn) Close() error                           { return nil }
func (authStateConn) LocalAddr() net.Addr                    { return testAddr("local") }
func (authStateConn) RemoteAddr() net.Addr                   { return testAddr("remote") }
func (authStateConn) SetDeadline(time.Time) error            { return nil }
func (authStateConn) SetReadDeadline(time.Time) error        { return nil }
func (authStateConn) SetWriteDeadline(time.Time) error       { return nil }

type authNoStateConn struct{}

func (authNoStateConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (authNoStateConn) Write(p []byte) (int, error)      { return len(p), nil }
func (authNoStateConn) Close() error                     { return nil }
func (authNoStateConn) LocalAddr() net.Addr              { return testAddr("local") }
func (authNoStateConn) RemoteAddr() net.Addr             { return testAddr("remote") }
func (authNoStateConn) SetDeadline(time.Time) error      { return nil }
func (authNoStateConn) SetReadDeadline(time.Time) error  { return nil }
func (authNoStateConn) SetWriteDeadline(time.Time) error { return nil }

func newAuthPrincipal(uris ...*url.URL) Principal {
	return Principal{Conn: authStateConn{
		state: tls.ConnectionState{
			VerifiedChains: [][]*x509.Certificate{{
				{URIs: uris},
			}},
		},
	}}
}

func mustParseAuthURL(t *testing.T, raw string) *url.URL {
	t.Helper()

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	return u
}
