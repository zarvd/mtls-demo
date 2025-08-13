package mtls

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

var (
	ErrAppendCACertsFromPEM               = errors.New("append CA certs from PEM")
	ErrLoadCertificateAndKeyFromLocalFile = errors.New("load certificate and key from local file")
)

// TLSKeyPair represents a TLS certificate, private key, and CA pool.
type TLSKeyPair struct {
	Certificate *tls.Certificate // Certificate is the certificate to use.
	CAs         *x509.CertPool   // CAs is the CA pool to use.
	Raw         *TLSKeyPairRaw   // Raw is the raw bytes of the key pair.
}

func (k *TLSKeyPair) Equal(other *TLSKeyPair) bool {
	return k.Raw.Equal(other.Raw)
}

type TLSKeyPairRaw struct {
	caBytes   []byte
	certBytes []byte
	keyBytes  []byte
}

func (s *TLSKeyPairRaw) Equal(other *TLSKeyPairRaw) bool {
	return bytes.Equal(s.caBytes, other.caBytes) &&
		bytes.Equal(s.certBytes, other.certBytes) &&
		bytes.Equal(s.keyBytes, other.keyBytes)
}

func (s *TLSKeyPairRaw) Parse() (*TLSKeyPair, error) {
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(s.caBytes) {
		return nil, ErrAppendCACertsFromPEM
	}
	cert, err := tls.X509KeyPair(s.certBytes, s.keyBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLoadCertificateAndKeyFromLocalFile, err)
	}
	return &TLSKeyPair{
		Certificate: &cert,
		CAs:         caPool,
		Raw:         s,
	}, nil
}
