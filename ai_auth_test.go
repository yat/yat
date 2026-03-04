package yat_test

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/url"
	"testing"
	"time"

	"yat.io/yat"
)

func TestNewRuleSet(t *testing.T) {
	t.Run("valid rules", func(t *testing.T) {
		_, err := yat.NewRuleSet([]yat.Rule{
			{
				Grants: []yat.Grant{{
					Path:    yat.NewPath("public/**"),
					Actions: []yat.Action{yat.ActionSub},
				}},
			},
			{
				SPIFFE: &yat.SPIFFESpec{
					Domain: "example.org",
					Path:   yat.NewPath("svc/*"),
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
					Path:    yat.NewPath("topic"),
					Actions: []yat.Action{yat.ActionPub},
				}},
			}},
		},
		{
			name: "invalid spiffe domain",
			rules: []yat.Rule{{
				SPIFFE: &yat.SPIFFESpec{Domain: "Example.Org"},
				Grants: []yat.Grant{{
					Path:    yat.NewPath("topic"),
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
					Path: yat.NewPath("topic"),
				}},
			}},
		},
		{
			name: "invalid grant action",
			rules: []yat.Rule{{
				Grants: []yat.Grant{{
					Path:    yat.NewPath("topic"),
					Actions: []yat.Action{"delete"},
				}},
			}},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := yat.NewRuleSet(tc.rules); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestRuleSetCompile(t *testing.T) {
	rs, err := yat.NewRuleSet([]yat.Rule{
		{
			Grants: []yat.Grant{{
				Path:    yat.NewPath("public/**"),
				Actions: []yat.Action{yat.ActionSub},
			}},
		},
		{
			SPIFFE: &yat.SPIFFESpec{Domain: "example.org"},
			Grants: []yat.Grant{{
				Path:    yat.NewPath("private/**"),
				Actions: []yat.Action{yat.ActionSub},
			}},
		},
		{
			SPIFFE: &yat.SPIFFESpec{
				Domain: "example.org",
				Path:   yat.NewPath("svc/*"),
			},
			Grants: []yat.Grant{{
				Path:    yat.NewPath("publish/**"),
				Actions: []yat.Action{yat.ActionPub},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	anon := rs.Compile(yat.Principal{})
	if !anon(yat.NewPath("public/feed"), yat.ActionSub) {
		t.Fatal("anonymous public access denied")
	}
	if anon(yat.NewPath("private/feed"), yat.ActionSub) {
		t.Fatal("anonymous spiffe grant allowed")
	}

	authd := rs.Compile(yat.Principal{
		Conn: newExternalAuthConn(t, "spiffe://example.org/svc/api"),
	})
	if !authd(yat.NewPath("public/feed"), yat.ActionSub) {
		t.Fatal("authenticated public access denied")
	}
	if !authd(yat.NewPath("private/feed"), yat.ActionSub) {
		t.Fatal("domain grant denied")
	}
	if !authd(yat.NewPath("publish/feed"), yat.ActionPub) {
		t.Fatal("path grant denied")
	}
	if authd(yat.NewPath("publish/feed"), yat.ActionSub) {
		t.Fatal("unexpected publish sub grant")
	}

	other := rs.Compile(yat.Principal{
		Conn: newExternalAuthConn(t, "spiffe://other.org/svc/api"),
	})
	if other(yat.NewPath("private/feed"), yat.ActionSub) {
		t.Fatal("unexpected other-domain grant")
	}
}

func TestAllowAll(t *testing.T) {
	allow := yat.AllowAll().Compile(yat.Principal{})

	if !allow(yat.NewPath("topic/pub"), yat.ActionPub) {
		t.Fatal("pub denied")
	}
	if !allow(yat.NewPath("topic/sub"), yat.ActionSub) {
		t.Fatal("sub denied")
	}
}

type externalAuthConn struct {
	state tls.ConnectionState
}

func (c externalAuthConn) ConnectionState() tls.ConnectionState { return c.state }
func (externalAuthConn) Read([]byte) (int, error)               { return 0, io.EOF }
func (externalAuthConn) Write(p []byte) (int, error)            { return len(p), nil }
func (externalAuthConn) Close() error                           { return nil }
func (externalAuthConn) LocalAddr() net.Addr                    { return externalAuthAddr("local") }
func (externalAuthConn) RemoteAddr() net.Addr                   { return externalAuthAddr("remote") }
func (externalAuthConn) SetDeadline(time.Time) error            { return nil }
func (externalAuthConn) SetReadDeadline(time.Time) error        { return nil }
func (externalAuthConn) SetWriteDeadline(time.Time) error       { return nil }

type externalAuthAddr string

func (a externalAuthAddr) Network() string { return "test" }
func (a externalAuthAddr) String() string  { return string(a) }

func newExternalAuthConn(t *testing.T, raw string) net.Conn {
	t.Helper()

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	return externalAuthConn{
		state: tls.ConnectionState{
			VerifiedChains: [][]*x509.Certificate{{
				{URIs: []*url.URL{u}},
			}},
		},
	}
}
