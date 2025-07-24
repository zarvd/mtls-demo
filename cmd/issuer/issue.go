package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

const (
	Country    = "CN"
	Province   = "Guangdong"
	City       = "Shenzhen"
	CommonName = "CA"
	Email      = "mtls-ca@zarvd.dev"
)

func mustMakeCA() *KeyPair {
	now := time.Now()
	ca, err := makeCertificateAuthority(pkix.Name{
		Country:    []string{Country},
		Province:   []string{Province},
		Locality:   []string{City},
		CommonName: fmt.Sprintf("mtls-ca-%s", now.Format(time.DateTime)),
	})
	if err != nil {
		panic(fmt.Errorf("make CA: %w", err))
	}

	return ca
}

func mustMakeServerCertificate(ca *KeyPair) *KeyPair {
	server, err := makeServerCertificate(ca, pkix.Name{
		Country:    []string{Country},
		Province:   []string{Province},
		Locality:   []string{City},
		CommonName: "mtls-server",
	}, []string{"mtls-server.zarvd.dev"})
	if err != nil {
		panic(fmt.Errorf("make server: %w", err))
	}

	return server
}

func mustMakeClientCertificate(ca *KeyPair) *KeyPair {
	client, err := makeClientCertificate(ca, pkix.Name{
		Country:    []string{Country},
		Province:   []string{Province},
		Locality:   []string{City},
		CommonName: "mtls-client",
	}, []string{"mtls-client.zarvd.dev"})
	if err != nil {
		panic(fmt.Errorf("make client: %w", err))
	}

	return client
}

const (
	CADuration          = 30 * time.Minute
	CertificateDuration = 10 * time.Minute
	RSASize             = 4096
)

func mustGenerateRSAPrivateKey() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, RSASize)
	if err != nil {
		panic(fmt.Errorf("generate key: %w", err))
	}
	return key
}

func makeCertificateAuthority(subject pkix.Name) (*KeyPair, error) {
	now := time.Now()
	cert := &x509.Certificate{
		Subject:      subject,
		SerialNumber: big.NewInt(now.Unix()),
		NotBefore:    now,
		NotAfter:     now.Add(CADuration),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
	}

	key := mustGenerateRSAPrivateKey()
	ca := &KeyPair{
		Certificate: cert,
		PrivateKey:  key,
	}
	ca.CA = ca
	return ca, nil
}

func loadCertificateAuthority(certPath, keyPath string) (*KeyPair, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load CA: %w", err)
	}

	rv := &KeyPair{
		Certificate: cert.Leaf,
		PrivateKey:  cert.PrivateKey.(*rsa.PrivateKey),
	}
	rv.CA = rv
	return rv, nil
}

func makeServerCertificate(
	ca *KeyPair,
	subject pkix.Name,
	altNames []string,
) (*KeyPair, error) {
	now := time.Now()
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(now.Unix()),
		Subject:      subject,
		DNSNames:     altNames,
		NotBefore:    now,
		NotAfter:     now.Add(CertificateDuration),
		IsCA:         false,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	key := mustGenerateRSAPrivateKey()
	kp := &KeyPair{
		Certificate: cert,
		PrivateKey:  key,
		CA:          ca,
	}

	return kp, nil
}

func makeClientCertificate(
	ca *KeyPair,
	subject pkix.Name,
	altNames []string,
) (*KeyPair, error) {
	now := time.Now()
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(now.Unix()),
		Subject:      subject,
		DNSNames:     altNames,
		NotBefore:    now,
		NotAfter:     now.Add(CertificateDuration),
		IsCA:         false,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	key := mustGenerateRSAPrivateKey()
	kp := &KeyPair{
		Certificate: cert,
		PrivateKey:  key,
		CA:          ca,
	}

	return kp, nil
}
