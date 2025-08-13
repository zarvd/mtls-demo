package mtls

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntegrationHTTP(t *testing.T) {
	t.Parallel()

	var (
		serverName    = "test-server"
		clientName    = "test-client"
		ca            = fakeCA(fakeCATemplate())
		serverKeyPair = ca.Sign(fakeServerTemplate(func(template *x509.Certificate) {
			template.Subject.CommonName = serverName
			template.DNSNames = []string{serverName}
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")} // allow localhost
		}))
		clientKeyPair = ca.Sign(fakeClientTemplate(func(template *x509.Certificate) {
			template.Subject.CommonName = clientName
		}))

		secondServerName    = "test-server-2"
		secondClientName    = "test-client-2"
		secondCA            = fakeCA(fakeCATemplate())
		secondServerKeyPair = secondCA.Sign(fakeServerTemplate(func(template *x509.Certificate) {
			template.Subject.CommonName = secondServerName
			template.DNSNames = []string{secondServerName}
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")} // allow localhost
		}))
		secondClientKeyPair = secondCA.Sign(fakeClientTemplate(func(template *x509.Certificate) {
			template.Subject.CommonName = secondClientName
		}))
	)

	t.Run("error if server certificate not trusted by client", func(t *testing.T) {
		t.Parallel()
		serverFs := MustTempKeyPairFiles()
		defer serverFs.Close()
		serverFs.SaveCA(ca)
		serverFs.SaveCertificate(serverKeyPair.Certificate)
		serverFs.SaveKey(serverKeyPair.Certificate.PrivateKey)

		clientFs := MustTempKeyPairFiles()
		defer clientFs.Close()
		clientFs.SaveCA(secondCA) // use a different CA which does not trust the server
		clientFs.SaveCertificate(secondClientKeyPair.Certificate)
		clientFs.SaveKey(secondClientKeyPair.Certificate.PrivateKey)

		serverLoader, err := NewLocalFileServerTLSConfigLoader(LocalFileTLSConfigLoaderOptions{
			CABundle:       serverFs.CA.Name(),
			Certificate:    serverFs.Certificate.Name(),
			Key:            serverFs.Key.Name(),
			ReloadInterval: 500 * time.Millisecond,
		})
		require.NoError(t, err)

		clientLoader, err := NewLocalFileClientTLSConfigLoader(LocalFileTLSConfigLoaderOptions{
			CABundle:       clientFs.CA.Name(),
			Certificate:    clientFs.Certificate.Name(),
			Key:            clientFs.Key.Name(),
			ReloadInterval: 500 * time.Millisecond,
		})
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		var (
			svrErrCh = make(chan error, 1)
			cliErrCh = make(chan error, 1)
		)
		go func() { svrErrCh <- serverLoader.StartLoop(ctx) }()
		go func() { cliErrCh <- clientLoader.StartLoop(ctx) }()

		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		server.TLS = serverLoader.ServerTLSConfig()
		server.StartTLS()
		defer server.Close()

		client := &http.Client{
			Transport: clientLoader.HTTPRoundTripper(),
		}

		_, err = client.Get(server.URL)
		require.Error(t, err)
		var unknownAuthorityError x509.UnknownAuthorityError
		require.ErrorAs(t, err, &unknownAuthorityError)
		assert.Equal(t, serverKeyPair.Certificate.Leaf, unknownAuthorityError.Cert)

		cancel()
		require.NoError(t, <-svrErrCh)
		require.NoError(t, <-cliErrCh)
	})

	t.Run("ok", func(t *testing.T) {
		t.Parallel()
		serverFs := MustTempKeyPairFiles()
		defer serverFs.Close()
		serverFs.Save(ca, serverKeyPair)

		clientFs := MustTempKeyPairFiles()
		defer clientFs.Close()
		clientFs.Save(ca, clientKeyPair)

		serverLoader, err := NewLocalFileServerTLSConfigLoader(LocalFileTLSConfigLoaderOptions{
			CABundle:       serverFs.CA.Name(),
			Certificate:    serverFs.Certificate.Name(),
			Key:            serverFs.Key.Name(),
			ReloadInterval: 500 * time.Millisecond,
		})
		require.NoError(t, err)

		clientLoader, err := NewLocalFileClientTLSConfigLoader(LocalFileTLSConfigLoaderOptions{
			CABundle:       clientFs.CA.Name(),
			Certificate:    clientFs.Certificate.Name(),
			Key:            clientFs.Key.Name(),
			ReloadInterval: 500 * time.Millisecond,
		})
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		var (
			svrErrCh = make(chan error, 1)
			cliErrCh = make(chan error, 1)
		)
		go func() { svrErrCh <- serverLoader.StartLoop(ctx) }()
		go func() { cliErrCh <- clientLoader.StartLoop(ctx) }()

		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		server.TLS = serverLoader.ServerTLSConfig()
		server.StartTLS()
		defer server.Close()

		client := &http.Client{
			Transport: clientLoader.HTTPRoundTripper(),
		}

		resp, err := client.Get(server.URL)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		cancel()
		require.NoError(t, <-svrErrCh)
		require.NoError(t, <-cliErrCh)
	})

	t.Run("ok and reload certificate", func(t *testing.T) {
		t.Parallel()
		serverFs := MustTempKeyPairFiles()
		defer serverFs.Close()
		serverFs.SaveCA(ca)
		serverFs.SaveCertificate(serverKeyPair.Certificate)
		serverFs.SaveKey(serverKeyPair.Certificate.PrivateKey)

		clientFs := MustTempKeyPairFiles()
		defer clientFs.Close()
		clientFs.SaveCA(ca)
		clientFs.SaveCertificate(clientKeyPair.Certificate)
		clientFs.SaveKey(clientKeyPair.Certificate.PrivateKey)

		serverLoader, err := NewLocalFileServerTLSConfigLoader(LocalFileTLSConfigLoaderOptions{
			CABundle:       serverFs.CA.Name(),
			Certificate:    serverFs.Certificate.Name(),
			Key:            serverFs.Key.Name(),
			ReloadInterval: 500 * time.Millisecond,
		})
		require.NoError(t, err)

		clientLoader, err := NewLocalFileClientTLSConfigLoader(LocalFileTLSConfigLoaderOptions{
			CABundle:       clientFs.CA.Name(),
			Certificate:    clientFs.Certificate.Name(),
			Key:            clientFs.Key.Name(),
			ReloadInterval: 500 * time.Millisecond,
		})
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		var (
			svrErrCh = make(chan error, 1)
			cliErrCh = make(chan error, 1)
		)
		go func() { svrErrCh <- serverLoader.StartLoop(ctx) }()
		go func() { cliErrCh <- clientLoader.StartLoop(ctx) }()

		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		server.TLS = serverLoader.ServerTLSConfig()
		server.StartTLS()
		defer server.Close()

		// First request should be successful (both server and client use the same CA)
		client := &http.Client{
			Transport: clientLoader.HTTPRoundTripper(),
		}
		resp, err := client.Get(server.URL)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		client.CloseIdleConnections()

		// Update server certificate
		serverFs.Save(secondCA, secondServerKeyPair)

		// Second request should not be successful (server uses a different CA)
		time.Sleep(500 * time.Millisecond)
		resp, err = client.Get(server.URL)
		require.Error(t, err)
		var unknownAuthorityError x509.UnknownAuthorityError
		require.ErrorAs(t, err, &unknownAuthorityError)
		assert.Equal(t, secondServerKeyPair.Certificate.Leaf, unknownAuthorityError.Cert)

		// Update client certificate
		clientFs.Save(secondCA, secondClientKeyPair)
		client.CloseIdleConnections()

		// Third request should be successful (client uses the updated certificate)
		time.Sleep(500 * time.Millisecond)
		resp, err = client.Get(server.URL)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		cancel()
		require.NoError(t, <-svrErrCh)
		require.NoError(t, <-cliErrCh)
	})
}
