// Package pkigen generates root CAs, intermediate CAs, and leaf certs for dev and tests.
// This package is not suitable for generating production credentials!
package pkigen

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"sync"
	"time"
)

// CertOpt is an option for NewRoot, NewBranch, or NewLeaf.
type CertOpt func(*x509.Certificate) error

var serMu = new(sync.Mutex)
var serials = make(map[*ecdsa.PrivateKey]uint64)

// Subject returns an option to set a cert's subject to the given name.
func Subject(name pkix.Name) CertOpt {
	return func(tmpl *x509.Certificate) error {
		tmpl.Subject = name
		return nil
	}
}

// CN returns an option to set a cert's subject to a name including the given common
// name. To set other properties of the subject, use WithSubject.
func CN(cn string) CertOpt {
	return Subject(pkix.Name{CommonName: cn})
}

// DNS returns an option to add a DNS SAN to the cert.
func DNS(name string) CertOpt {
	return func(tmpl *x509.Certificate) error {
		tmpl.DNSNames = append(tmpl.DNSNames, name)
		return nil
	}
}

// Email returns an option to add an email address SAN to the cert.
func Email(email string) CertOpt {
	return func(tmpl *x509.Certificate) error {
		tmpl.EmailAddresses = append(tmpl.EmailAddresses, email)
		return nil
	}
}

// IP returns an option to add an IP SAN to the cert.
func IP(ip net.IP) CertOpt {
	return func(tmpl *x509.Certificate) error {
		tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		return nil
	}
}

// URI returns an option to add a URI SAN to the cert.
func URI(s string) CertOpt {
	return func(tmpl *x509.Certificate) error {
		u, err := url.Parse(s)
		if err != nil {
			return err
		}

		tmpl.URIs = append(tmpl.URIs, u)
		return nil
	}
}

// NewRoot creates a new self-signed CA and returns its certificate and keypair. By
// default the CA has a name like "pkigen root CA 1234567890" and expires in 10 years. The
// cert and key can be used to sign other certs, but they can't be used for mtls.
func NewRoot(opts ...CertOpt) (crt *x509.Certificate, key *ecdsa.PrivateKey, err error) {
	now := time.Now()
	key, err = newKey()
	if err != nil {
		return
	}

	name := pkix.Name{
		CommonName: fmt.Sprintf("pkigen root CA %d", now.Unix()),
	}

	tmpl := x509.Certificate{
		SerialNumber: nextSerial(key),
		Subject:      name,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,

		NotBefore: now,
		NotAfter:  now.AddDate(10, 0, 0),

		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	for _, opt := range opts {
		err = opt(&tmpl)
		if err != nil {
			return
		}
	}

	crt, err = newCert(&tmpl, &tmpl, key.Public(), key)

	return
}

// NewBranch creates a new intermediate CA and returns its certificate and keypair. The
// cert is signed by signer. By default the CA has a name like "pkigen branch CA 1234567890"
// and expires in 5 years. The returned cert and key can be used to sign other certs, but
// they can't be used for mtls.
func NewBranch(parent *x509.Certificate, signer *ecdsa.PrivateKey, opts ...CertOpt) (crt *x509.Certificate, key *ecdsa.PrivateKey, err error) {
	now := time.Now()
	key, err = newKey()
	if err != nil {
		return
	}

	name := pkix.Name{
		CommonName: fmt.Sprintf("pkigen branch CA %d", now.Unix()),
	}

	tmpl := x509.Certificate{
		SerialNumber: nextSerial(signer),
		Subject:      name,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,

		NotBefore: now,
		NotAfter:  now.AddDate(5, 0, 0),

		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	for _, opt := range opts {
		err = opt(&tmpl)
		if err != nil {
			return
		}
	}

	crt, err = newCert(&tmpl, parent, key.Public(), signer)

	return
}

// NewLeaf returns a new leaf certificate and keypair. The cert is signed by signer. By
// default the leaf is named "pkigen leaf" and expires in 1 year. The returned cert and key
// can be used for mtls.
func NewLeaf(parent *x509.Certificate, signer *ecdsa.PrivateKey, opts ...CertOpt) (crt *x509.Certificate, key *ecdsa.PrivateKey, err error) {
	now := time.Now()
	key, err = newKey()
	if err != nil {
		return
	}

	name := pkix.Name{
		CommonName: "pkigen leaf",
	}

	tmpl := x509.Certificate{
		SerialNumber: nextSerial(signer),
		Subject:      name,
		KeyUsage:     x509.KeyUsageDigitalSignature,

		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},

		NotBefore: now,
		NotAfter:  now.AddDate(1, 0, 0),

		BasicConstraintsValid: true,
	}

	for _, opt := range opts {
		err = opt(&tmpl)
		if err != nil {
			return
		}
	}

	crt, err = newCert(&tmpl, parent, key.Public(), signer)

	return
}

// ecdsa keys because they're more compatible with browsers today
func newKey() (key *ecdsa.PrivateKey, err error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func newCert(template *x509.Certificate, parent *x509.Certificate, pubKey crypto.PublicKey, signer *ecdsa.PrivateKey) (crt *x509.Certificate, err error) {
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pubKey, signer)
	if err != nil {
		return
	}

	return x509.ParseCertificate(der)
}

func nextSerial(key *ecdsa.PrivateKey) *big.Int {
	serMu.Lock()
	serials[key]++
	ser := serials[key]
	serMu.Unlock()
	return big.NewInt(int64(ser))
}
