package mtls

import (
	"crypto/tls"
)

func CreateTLSConfigForServer(loader interface{ KeyPair() *TLSKeyPair }) *tls.Config {
	getConfigForClient := func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		keyPair := loader.KeyPair()
		return &tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  keyPair.CAs,
			GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return keyPair.Certificate, nil
			},
		}, nil
	}

	return &tls.Config{
		GetConfigForClient: getConfigForClient,
	}
}
