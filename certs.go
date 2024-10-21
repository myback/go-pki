package pki

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

type CA struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
}

type Certificate struct {
	cert *x509.Certificate
	raw  []byte
}

func (ca *CA) Certificate() *Certificate {
	return &Certificate{cert: ca.cert}
}

func (crt *Certificate) PEM() []byte {
	bytes := crt.raw
	if bytes == nil {
		bytes = crt.cert.Raw
	}

	block := &pem.Block{Type: "CERTIFICATE", Bytes: bytes}
	return pem.EncodeToMemory(block)
}

func (crt *Certificate) Save(certFile string) error {
	if err := os.WriteFile(certFile, crt.PEM(), 0644); err != nil {
		return fmt.Errorf("could not write certificate %q: %v", certFile, err)
	}
	return nil
}
