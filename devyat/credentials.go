package devyat

import (
	"crypto"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"

	"yat.io/yat/pkigen"
)

// GenerateCreds writes client and server development credentials to files under dir.
// The files are tls/ca.crt, tls/server.crt, tls/server.key, tls/client.crt, and tls/client.key.
// If any file is missing, all of the files are regenerated.
func GenerateCreds(dir string, hostname string) (generated bool, err error) {
	var (
		tlsDir            = filepath.Join(dir, "tls")
		tlsCAFile         = filepath.Join(tlsDir, "ca.crt")
		tlsSvrCertFile    = filepath.Join(tlsDir, "server.crt")
		tlsSvrKeyFile     = filepath.Join(tlsDir, "server.key")
		tlsClientCertFile = filepath.Join(tlsDir, "client.crt")
		tlsClientKeyFile  = filepath.Join(tlsDir, "client.key")
	)

	tlsFiles := []string{
		tlsCAFile,
		tlsSvrCertFile,
		tlsSvrKeyFile,
		tlsClientCertFile,
		tlsClientKeyFile,
	}

	tlsOK := true
	for _, name := range tlsFiles {
		if _, err := os.Stat(name); err != nil {
			tlsOK = false
			break
		}
	}

	if !tlsOK {
		if err := os.RemoveAll(tlsDir); err != nil {
			return false, err
		}

		if err := os.MkdirAll(tlsDir, 0755); err != nil {
			return false, err
		}

		caCrt, caKey, err := pkigen.NewRoot()
		if err != nil {
			return false, err
		}

		var san pkigen.CertOpt

		ip := net.ParseIP(hostname)

		switch {
		case ip != nil:
			san = pkigen.IP(ip)
		default:
			san = pkigen.DNS(hostname)
		}

		svrCrt, svrKey, err := pkigen.NewLeaf(caCrt, caKey, san)
		if err != nil {
			return false, err
		}

		clientCrt, clientKey, err := pkigen.NewLeaf(caCrt, caKey, pkigen.CN("yat client"))
		if err != nil {
			return false, err
		}

		if err := writeCertFile(tlsCAFile, caCrt); err != nil {
			return false, err
		}

		if err := writeCertFile(tlsSvrCertFile, svrCrt); err != nil {
			return false, err
		}

		if err := writePrivateKeyFile(tlsSvrKeyFile, svrKey); err != nil {
			return false, err
		}

		if err := writeCertFile(tlsClientCertFile, clientCrt); err != nil {
			return false, err
		}

		if err := writePrivateKeyFile(tlsClientKeyFile, clientKey); err != nil {
			return false, err
		}

		generated = true
	}

	return
}

// writeCertFile PEM-encodes the certificates and writes them to the named file.
// If the file doesn't exist, it is created with mode 0644.
func writeCertFile(name string, certs ...*x509.Certificate) error {
	return os.WriteFile(name, pkigen.EncodeCerts(certs...), 0644)
}

// writePrivateKeyFile PEM-encodes the key and writes it to the named file.
// If the file doesn't exist, it is created with mode 0600.
func writePrivateKeyFile(name string, key crypto.PrivateKey) error {
	keyPEM, err := pkigen.EncodePrivateKey(key)
	if err != nil {
		return err
	}

	return os.WriteFile(name, keyPEM, 0600)
}
