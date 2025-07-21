package keypair

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"sync"
)

const (
	mapKeyCAPool      = "ca_pool"
	mapKeyCACerts     = "ca_certs"
	mapKeyRawKeyPairs = "raw_key_pairs"
	mapKeyKeyPairs    = "key_pairs"
)

// bundleMap is a goroutine safe map of certificate authorities, certificates, and keys.
type bundleMap struct {
	inner sync.Map
}

func (m *bundleMap) GetCAPool() (*x509.CertPool, bool) {
	caPool, ok := m.inner.Load(mapKeyCAPool)
	if !ok {
		return nil, false
	}
	return caPool.(*x509.CertPool), true
}

func (m *bundleMap) StoreCAPool(caPool *x509.CertPool) {
	m.inner.Store(mapKeyCAPool, caPool)
}

func (m *bundleMap) GetCAPEMs() ([][]byte, bool) {
	caPEMs, ok := m.inner.Load(mapKeyCACerts)
	if !ok {
		return nil, false
	}
	return caPEMs.([][]byte), true
}

func (m *bundleMap) StoreCAPEMs(caPEMs [][]byte) {
	m.inner.Store(mapKeyCACerts, caPEMs)
}

type RawKeyPair struct {
	cert []byte
	key  []byte
}

func (r *RawKeyPair) Equal(other RawKeyPair) bool {
	return bytes.Equal(r.cert, other.cert) && bytes.Equal(r.key, other.key)
}

func RawKeyPairsEqual(a, b []RawKeyPair) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}

func (m *bundleMap) GetRawKeyPairs() ([]RawKeyPair, bool) {
	keyPairs, ok := m.inner.Load(mapKeyRawKeyPairs)
	if !ok {
		return nil, false
	}
	return keyPairs.([]RawKeyPair), true
}

func (m *bundleMap) StoreRawKeyPairs(keyPairs []RawKeyPair) {
	m.inner.Store(mapKeyRawKeyPairs, keyPairs)
}

func (m *bundleMap) GetKeyPairs() ([]tls.Certificate, bool) {
	keyPairs, ok := m.inner.Load(mapKeyKeyPairs)
	if !ok {
		return nil, false
	}
	return keyPairs.([]tls.Certificate), true
}

func (m *bundleMap) StoreKeyPairs(keyPairs []tls.Certificate) {
	m.inner.Store(mapKeyKeyPairs, keyPairs)
}
