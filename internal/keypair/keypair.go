package keypair

import (
	"crypto/tls"
	"crypto/x509"
)

type KeyPair struct {
	Certificate *tls.Certificate
	CAPool      *x509.CertPool
}
