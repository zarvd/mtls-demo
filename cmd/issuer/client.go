package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

func makeClientCertificate(
	ca *KeyPair,
	subject pkix.Name,
	altNames []string,
) (*KeyPair, error) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2025 + 123),
		Subject:      subject,
		DNSNames:     altNames,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * time.Hour),
		IsCA:         false,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	kp := &KeyPair{
		Certificate: cert,
		PrivateKey:  key,
		CA:          ca,
	}

	return kp, nil
}
