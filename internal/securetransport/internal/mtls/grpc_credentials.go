package mtls

import (
	"context"
	"crypto/tls"
	"net"
	"sync/atomic"

	"google.golang.org/grpc/credentials"
)

var _ credentials.TransportCredentials = (*dynamicTLSCredentials)(nil)

type dynamicTLSCredentials struct {
	loader interface{ KeyPair() *TLSKeyPair }
	inner  atomic.Pointer[credentialsWithKeyPair]
}

type credentialsWithKeyPair struct {
	Credentials credentials.TransportCredentials
	KeyPair     *TLSKeyPair
}

func CreateDynamicTLSCredentials(loader interface{ KeyPair() *TLSKeyPair }) credentials.TransportCredentials {
	return &dynamicTLSCredentials{loader: loader}
}

func (d *dynamicTLSCredentials) ClientHandshake(
	ctx context.Context,
	authority string,
	conn net.Conn,
) (net.Conn, credentials.AuthInfo, error) {
	return d.innerCredentials().ClientHandshake(ctx, authority, conn)
}
func (d *dynamicTLSCredentials) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return d.innerCredentials().ServerHandshake(conn)
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
	nextKeyPair := d.loader.KeyPair()
	if inner != nil && inner.KeyPair.Equal(nextKeyPair) {
		return inner.Credentials
	}
	// Create new credentials.
	cred := credentials.NewTLS(&tls.Config{
		RootCAs:      nextKeyPair.CAs,
		Certificates: []tls.Certificate{*nextKeyPair.Certificate},
	})
	d.inner.Store(&credentialsWithKeyPair{
		Credentials: cred,
		KeyPair:     nextKeyPair,
	})
	return cred
}
