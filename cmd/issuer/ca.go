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

func makeCertificateAuthority(subject pkix.Name) (*KeyPair, error) {
	cert := &x509.Certificate{
		Subject:      subject,
		SerialNumber: big.NewInt(2025),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
	}

	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("generate CA private key: %w", err)
	}

	ca := &KeyPair{
		Certificate: cert,
		PrivateKey:  key,
	}
	ca.CA = ca
	return ca, nil
}
