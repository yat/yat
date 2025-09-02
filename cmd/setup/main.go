// Setup generates dev creds.
package main

import (
	"crypto"
	"crypto/x509"
	"net"
	"os"

	"github.com/yat/yat/pkigen"
)

// Generates:
//
//   - tmp/pki/root.crt
//   - tmp/pki/root.key
//   - tmp/pki/server.crt
//   - tmp/pki/server.key
//   - tmp/pki/client.crt
//   - tmp/pki/client.key

func main() {
	dirs := []string{
		"tmp/pki",
	}

	for _, dir := range dirs {
		if err := os.RemoveAll(dir); err != nil {
			panic(err)
		}

		if err := os.MkdirAll(dir, 0755); err != nil {
			panic(err)
		}
	}

	rootCrt, rootKey, err := pkigen.NewRoot()
	if err != nil {
		panic(err)
	}

	if err := writeCertFile("tmp/pki/root.crt", rootCrt); err != nil {
		panic(err)
	}

	if err := writeKeyFile("tmp/pki/root.key", rootKey); err != nil {
		panic(err)
	}

	serverCrt, serverKey, err := pkigen.NewLeaf(rootCrt, rootKey,
		pkigen.CN("yat server"),
		pkigen.IP(net.ParseIP("::1")))

	if err != nil {
		panic(err)
	}

	if err := writeCertFile("tmp/pki/server.crt", serverCrt); err != nil {
		panic(err)
	}

	if err := writeKeyFile("tmp/pki/server.key", serverKey); err != nil {
		panic(err)
	}

	clientCrt, clientKey, err := pkigen.NewLeaf(rootCrt, rootKey,
		pkigen.CN("yat client"))
	if err != nil {
		panic(err)
	}

	if err := writeCertFile("tmp/pki/client.crt", clientCrt); err != nil {
		panic(err)
	}

	if err := writeKeyFile("tmp/pki/client.key", clientKey); err != nil {
		panic(err)
	}
}

// writeCertFile PEM-encodes the certificates and writes them to the named file.
// If the file doesn't exist, it is created with mode 0644.
func writeCertFile(name string, certs ...*x509.Certificate) error {
	return os.WriteFile(name, pkigen.EncodeCerts(certs...), 0644)
}

// writeKeyFile PEM-encodes the key and writes it to the named file.
// If the file doesn't exist, it is created with mode 0600.
func writeKeyFile(name string, key crypto.PrivateKey) error {
	keyPEM, err := pkigen.EncodePrivateKey(key)
	if err != nil {
		return err
	}

	return os.WriteFile(name, keyPEM, 0600)
}
