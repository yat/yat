package pkigen

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// EncodeCerts returns a PEM-encoded slice containing a CERTIFICATE block for each cert.
func EncodeCerts(certs ...*x509.Certificate) (pemBytes []byte) {
	for _, cert := range certs {
		enc := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})

		pemBytes = append(pemBytes, enc...)
	}

	return
}

// EncodePrivateKey returns a PEM-encoded slice containing a PRIVATE KEY block for the given key.
func EncodePrivateKey(key crypto.PrivateKey) (pemBytes []byte, err error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return
	}

	enc := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})

	pemBytes = append(pemBytes, enc...)

	return
}

// EncodePublicKey returns a PEM-encoded slice containing a PUBLIC KEY block for the given key.
func EncodePublicKey(key crypto.PublicKey) (pemBytes []byte, err error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return
	}

	enc := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})

	pemBytes = append(pemBytes, enc...)

	return
}

func DecodePublicKey(pemBytes []byte) (key crypto.PublicKey, err error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM data")
	}

	key, err = x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}
