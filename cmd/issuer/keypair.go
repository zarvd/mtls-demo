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

func (kp *KeyPair) certificatePEM() ([]byte, error) {
	caBytes, err := x509.CreateCertificate(
		rand.Reader, kp.Certificate, kp.CA.Certificate, &kp.PrivateKey.PublicKey, kp.CA.PrivateKey,
	)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	return caPEM.Bytes(), nil
}

func (kp *KeyPair) SaveCertificate(path string) error {
	pemBytes, err := kp.certificatePEM()
	if err != nil {
		return fmt.Errorf("save certificate: %w", err)
	}
	return os.WriteFile(path, pemBytes, 0644)
}

func (kp *KeyPair) SavePrivateKey(path string) error {
	keyPEM := new(bytes.Buffer)
	pem.Encode(keyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(kp.PrivateKey),
	})

	return os.WriteFile(path, keyPEM.Bytes(), 0600)
}

func (kp *KeyPair) SaveBundleWith(keyPairs []*KeyPair, path string) error {
	keyPairs = append([]*KeyPair{kp}, keyPairs...)
	buf := new(bytes.Buffer)
	for i, keyPair := range keyPairs {
		caPEM, err := keyPair.certificatePEM()
		if err != nil {
			return fmt.Errorf("save bundle: %w", err)
		}
		if i > 0 {
			buf.Write([]byte("\n"))
		}
		buf.Write(caPEM)
	}

	return os.WriteFile(path, buf.Bytes(), 0644)
}
