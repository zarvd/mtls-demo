package mtls

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"sync/atomic"

	"google.golang.org/grpc/credentials"
)

var _ credentials.TransportCredentials = (*dynamicTLSCredentials)(nil)

type dynamicTLSCredentials struct {
	loader interface{ KeyPair() *TLSKeyPair }
	inner  atomic.Pointer[credentialsWithKeyPair]
	initMu sync.Mutex
}

type credentialsWithKeyPair struct {
	Credentials credentials.TransportCredentials
	KeyPair     *TLSKeyPair
}

func CreateDynamicTLSCredentials(
	loader interface{ KeyPair() *TLSKeyPair },
) credentials.TransportCredentials {
	return &dynamicTLSCredentials{loader: loader}
}

func (d *dynamicTLSCredentials) ClientHandshake(
	ctx context.Context,
	authority string,
	rawConn net.Conn,
) (net.Conn, credentials.AuthInfo, error) {
	return d.innerCredentials().ClientHandshake(ctx, authority, rawConn)
}

func (d *dynamicTLSCredentials) ServerHandshake(
	rawConn net.Conn,
) (net.Conn, credentials.AuthInfo, error) {
	return d.innerCredentials().ServerHandshake(rawConn)
}

func (d *dynamicTLSCredentials) Info() credentials.ProtocolInfo {
	return d.innerCredentials().Info()
}

func (d *dynamicTLSCredentials) Clone() credentials.TransportCredentials {
	return d // use the same object
}

func (d *dynamicTLSCredentials) OverrideServerName(serverNameOverride string) error {
	return d.innerCredentials().OverrideServerName(serverNameOverride)
}

// innerCredentials returns the actual credentials to use.
// If the key pair has changed, it will create a new credentials.TransportCredentials.
func (d *dynamicTLSCredentials) innerCredentials() credentials.TransportCredentials {
	inner := d.inner.Load()

	if inner != nil && inner.KeyPair.Equal(d.loader.KeyPair()) {
		return inner.Credentials
	}

	// singleflight
	d.initMu.Lock()
	defer d.initMu.Unlock()

	// Double check under lock.
	inner = d.inner.Load()
	if inner != nil && inner.KeyPair.Equal(d.loader.KeyPair()) {
		return inner.Credentials
	}

	// Create new credentials.
	keyPair := d.loader.KeyPair()
	tlsConfig := &tls.Config{
		RootCAs:      keyPair.CAs,
		Certificates: []tls.Certificate{*keyPair.Certificate},
	}
	cred := credentials.NewTLS(tlsConfig)
	d.inner.Store(&credentialsWithKeyPair{
		Credentials: cred,
		KeyPair:     keyPair,
	})

	return cred
}
