package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

type KeyPair struct {
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey

	CA *KeyPair
}

func (kp *KeyPair) SaveCertificate(path string) error {
	caBytes, err := x509.CreateCertificate(
		rand.Reader, kp.Certificate, kp.CA.Certificate, &kp.PrivateKey.PublicKey, kp.CA.PrivateKey,
	)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	return os.WriteFile(path, caPEM.Bytes(), 0644)
}

func (kp *KeyPair) SavePrivateKey(path string) error {
	keyPEM := new(bytes.Buffer)
	pem.Encode(keyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(kp.PrivateKey),
	})

	return os.WriteFile(path, keyPEM.Bytes(), 0600)
}
