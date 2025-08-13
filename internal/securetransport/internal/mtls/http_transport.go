package mtls

import (
	"crypto/tls"
	"net/http"
)

var _ http.RoundTripper = (*dynamicTLSTransport)(nil)

type dynamicTLSTransport struct {
	loader interface{ KeyPair() *TLSKeyPair }
}

func CreateDynamicTLSTransport(
	loader interface{ KeyPair() *TLSKeyPair },
) http.RoundTripper {
	return &dynamicTLSTransport{
		loader: loader,
	}
}

func (t *dynamicTLSTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	keyPair := t.loader.KeyPair()
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      keyPair.CAs,
			Certificates: []tls.Certificate{*keyPair.Certificate},
		},
	}
	return tr.RoundTrip(req)
}
