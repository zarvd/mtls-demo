package mtls

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

var (
	ErrAppendCACertsFromPEM               = errors.New("append CA certs from PEM")
	ErrLoadCertificateAndKeyFromLocalFile = errors.New("load certificate and key from local file")
)

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
	checkSum  []byte
}

func NewTLSKeyPairRaw(caBytes, certBytes, keyBytes []byte) *TLSKeyPairRaw {
	raw := &TLSKeyPairRaw{
		caBytes:   caBytes,
		certBytes: certBytes,
		keyBytes:  keyBytes,
	}
	raw.checkSum = raw.calculateCheckSum()
	return raw
}

func (s *TLSKeyPairRaw) calculateCheckSum() []byte {
	h := sha256.New()
	h.Write(s.caBytes)
	h.Write(s.certBytes)
	h.Write(s.keyBytes)
	return h.Sum(nil)
}

func (s *TLSKeyPairRaw) Equal(other *TLSKeyPairRaw) bool {
	return bytes.Equal(s.checkSum, other.checkSum)
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
