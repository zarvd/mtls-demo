package mtls

import (
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateDynamicTLSTransport(t *testing.T) {
	t.Parallel()

	const (
		ServerName = "test-server"
	)

	t.Run("it should verify both client and server certificates", func(t *testing.T) {
		t.Parallel()

		var (
			ca            = fakeCA(fakeCATemplate())
			serverKeyPair = ca.Sign(fakeServerTemplate(func(template *x509.Certificate) {
				template.Subject.CommonName = ServerName
				template.DNSNames = []string{ServerName}
				template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
			}))
			serverLoader    = &fakeKeyPairLoader{keyPair: serverKeyPair}
			clientKeyPair   = ca.Sign(fakeClientTemplate())
			clientLoader    = &fakeKeyPairLoader{keyPair: clientKeyPair}
			serverTLSConfig = CreateTLSConfigForServer(serverLoader)
			clientTransport = CreateDynamicTLSTransport(clientLoader)
		)

		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		server.TLS = serverTLSConfig
		server.StartTLS()
		defer server.Close()

		client := http.Client{
			Transport: clientTransport,
		}

		resp, err := client.Get(server.URL)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("it should return an error if the server certificate is not trusted", func(t *testing.T) {
		t.Parallel()

		var (
			ca            = fakeCA(fakeCATemplate())
			serverKeyPair = ca.Sign(fakeServerTemplate(func(template *x509.Certificate) {
				template.Subject.CommonName = ServerName
				template.DNSNames = []string{ServerName}
				template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
			}))
			serverLoader    = &fakeKeyPairLoader{keyPair: serverKeyPair}
			clientKeyPair   = ca.Sign(fakeClientTemplate())
			serverTLSConfig = CreateTLSConfigForServer(serverLoader)
		)

		clientKeyPair.CAs = fakeCA(fakeCATemplate()).pool() // use different CA pool for client
		clientLoader := &fakeKeyPairLoader{keyPair: clientKeyPair}
		clientTransport := CreateDynamicTLSTransport(clientLoader)

		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		server.TLS = serverTLSConfig
		server.StartTLS()
		defer server.Close()

		client := http.Client{
			Transport: clientTransport,
		}

		_, err := client.Get(server.URL)
		require.Error(t, err)
		var unknownAuthorityError x509.UnknownAuthorityError
		require.ErrorAs(t, err, &unknownAuthorityError)
		assert.Equal(t, serverKeyPair.Certificate.Leaf, unknownAuthorityError.Cert)
	})

	t.Run("it should return an error if the client certificate is not trusted", func(t *testing.T) {
		t.Parallel()

		var (
			ca            = fakeCA(fakeCATemplate())
			serverKeyPair = ca.Sign(fakeServerTemplate(func(template *x509.Certificate) {
				template.Subject.CommonName = ServerName
				template.DNSNames = []string{ServerName}
				template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
			}))
			clientKeyPair   = ca.Sign(fakeClientTemplate())
			clientLoader    = &fakeKeyPairLoader{keyPair: clientKeyPair}
			clientTransport = CreateDynamicTLSTransport(clientLoader)
		)

		serverKeyPair.CAs = fakeCA(fakeCATemplate()).pool() // use different CA pool for server
		serverLoader := &fakeKeyPairLoader{keyPair: serverKeyPair}
		serverTLSConfig := CreateTLSConfigForServer(serverLoader)

		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		server.TLS = serverTLSConfig
		server.StartTLS()
		defer server.Close()

		client := http.Client{
			Transport: clientTransport,
		}

		_, err := client.Get(server.URL)
		require.Error(t, err)
		const InternalTLSClientError = "unknown certificate authority"
		assert.ErrorContains(t, err, InternalTLSClientError)
	})

	t.Run("it should reload certificate when establish new connection", func(t *testing.T) {
		t.Parallel()

		var (
			ca            = fakeCA(fakeCATemplate())
			serverKeyPair = ca.Sign(fakeServerTemplate(func(template *x509.Certificate) {
				template.Subject.CommonName = ServerName
				template.DNSNames = []string{ServerName}
				template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
			}))
			serverLoader    = &fakeKeyPairLoader{keyPair: serverKeyPair}
			clientKeyPair   = ca.Sign(fakeClientTemplate())
			clientLoader    = &fakeKeyPairLoader{keyPair: clientKeyPair}
			serverTLSConfig = CreateTLSConfigForServer(serverLoader)
			clientTransport = CreateDynamicTLSTransport(clientLoader)
		)

		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		server.TLS = serverTLSConfig
		server.StartTLS()
		defer server.Close()

		// Successfully connect to server
		client := http.Client{
			Transport: clientTransport,
		}
		resp, err := client.Get(server.URL)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		client.CloseIdleConnections()

		// Switch to: server certificate is not trusted
		serverLoader.keyPair.CAs = fakeCA(fakeCATemplate()).pool()
		_, err = client.Get(server.URL)
		require.Error(t, err)
		const InternalTLSClientError = "unknown certificate authority"
		assert.ErrorContains(t, err, InternalTLSClientError)
		client.CloseIdleConnections()

		// Switch to: happy path
		serverLoader.keyPair.CAs = ca.pool()
		resp, err = client.Get(server.URL)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		client.CloseIdleConnections()

		// Switch to: client certificate is not trusted
		clientLoader.keyPair.CAs = fakeCA(fakeCATemplate()).pool()
		resp, err = client.Get(server.URL)
		require.Error(t, err)
		var unknownAuthorityError x509.UnknownAuthorityError
		require.ErrorAs(t, err, &unknownAuthorityError)
		assert.Equal(t, serverKeyPair.Certificate.Leaf, unknownAuthorityError.Cert)
		client.CloseIdleConnections()

		// Switch to: happy path
		clientLoader.keyPair.CAs = ca.pool()
		resp, err = client.Get(server.URL)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}
