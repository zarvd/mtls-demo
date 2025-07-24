package keypair

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"strings"
)

// KeyPair is a pair of certificate and CA pool.
// It's immutable.
type KeyPair struct {
	Certificate *tls.Certificate
	CAPool      *x509.CertPool
	rawCAPEM    []byte
}

func NewKeyPair(cert *tls.Certificate, caPEMCerts []byte) (*KeyPair, error) {
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEMCerts) {
		return nil, fmt.Errorf("failed to append certs from PEM")
	}
	return &KeyPair{Certificate: cert, CAPool: caPool, rawCAPEM: caPEMCerts}, nil
}

func (kp *KeyPair) String() string {
	return fmt.Sprintf("KeyPair{certificate: '%s', certificate-issuer: '%s', ca-pool: [%s]}",
		kp.Certificate.Leaf.Subject.CommonName,
		kp.Certificate.Leaf.Issuer.CommonName,
		strings.Join(ListCommonNames(kp.rawCAPEM), ", "),
	)
}

func ListCommonNames(pemCerts []byte) []string {
	var rv []string
	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			slog.Error("Failed to parse certificate", "error", err)
			continue
		}
		rv = append(rv, cert.Subject.CommonName)
	}
	return rv
}
