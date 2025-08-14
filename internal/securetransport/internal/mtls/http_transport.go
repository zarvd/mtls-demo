package mtls

import (
	"crypto/tls"
	"net/http"
	"sync/atomic"
)

var _ http.RoundTripper = (*dynamicTLSTransport)(nil)

type dynamicTLSTransport struct {
	loader interface{ KeyPair() *TLSKeyPair }
	inner  atomic.Pointer[transportWithKeyPair]
}

type transportWithKeyPair struct {
	Transport *http.Transport
	KeyPair   *TLSKeyPair
}

func CreateDynamicTLSTransport(
	loader interface{ KeyPair() *TLSKeyPair },
) http.RoundTripper {
	return &dynamicTLSTransport{
		loader: loader,
	}
}

func (t *dynamicTLSTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.innerTransport().RoundTrip(req)
}

func (t *dynamicTLSTransport) CloseIdleConnections() {
	t.innerTransport().CloseIdleConnections()
}

func (t *dynamicTLSTransport) innerTransport() *http.Transport {
	inner := t.inner.Load()
	nextKeyPair := t.loader.KeyPair()
	if inner != nil && inner.KeyPair.Equal(nextKeyPair) {
		return inner.Transport
	}
	// Close idle connections
	if inner != nil {
		inner.Transport.CloseIdleConnections()
	}
	// Create new transport.
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      nextKeyPair.CAs,
			Certificates: []tls.Certificate{*nextKeyPair.Certificate},
		},
	}
	t.inner.Store(&transportWithKeyPair{
		Transport: tr,
		KeyPair:   nextKeyPair,
	})
	return tr
}
