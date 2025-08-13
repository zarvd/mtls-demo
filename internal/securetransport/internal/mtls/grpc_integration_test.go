package mtls

import (
	"context"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/test/bufconn"

	"github.com/zarvd/mtls-demo/internal/securetransport/internal/mtls/fake"
)

func TestIntegrationGRPC(t *testing.T) {
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

		bufconn.Listen(1024 * 1024)
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

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		var (
			svrErrCh = make(chan error, 1)
			cliErrCh = make(chan error, 1)
		)
		go func() { svrErrCh <- serverLoader.StartLoop(ctx) }()
		go func() { cliErrCh <- clientLoader.StartLoop(ctx) }()

		lis := bufconn.Listen(1024 * 1024)
		defer lis.Close()

		server := grpc.NewServer(
			grpc.Creds(credentials.NewTLS(serverLoader.ServerTLSConfig())),
		)
		fake.RegisterStubService(server)

		var grpcErrCh = make(chan error, 1)
		go func() {
			grpcErrCh <- server.Serve(lis)
		}()

		conn, err := grpc.NewClient(
			serverName,
			grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
				return lis.Dial()
			}),
			grpc.WithTransportCredentials(clientLoader.GRPCCredentials()),
		)
		require.NoError(t, err)
		defer conn.Close()

		_, err = fake.InvokePing(ctx, conn)
		require.NoError(t, err)

		server.GracefulStop()
		cancel()
		require.NoError(t, <-grpcErrCh)
		require.NoError(t, <-svrErrCh)
		require.NoError(t, <-cliErrCh)
	})

	t.Run("ok and reload certificate", func(t *testing.T) {
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

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		var (
			svrErrCh = make(chan error, 1)
			cliErrCh = make(chan error, 1)
		)
		go func() { svrErrCh <- serverLoader.StartLoop(ctx) }()
		go func() { cliErrCh <- clientLoader.StartLoop(ctx) }()

		lis := bufconn.Listen(1024 * 1024)
		defer lis.Close()

		serverOptions := []grpc.ServerOption{
			grpc.Creds(credentials.NewTLS(serverLoader.ServerTLSConfig())),
		}
		server := grpc.NewServer(serverOptions...)
		fake.RegisterStubService(server)

		var grpcErrCh = make(chan error, 1)
		go func() {
			grpcErrCh <- server.Serve(lis)
		}()

		conn, err := grpc.NewClient(
			serverName,
			grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
				return lis.Dial()
			}),
			grpc.WithTransportCredentials(clientLoader.GRPCCredentials()),
		)
		require.NoError(t, err)
		defer conn.Close()

		// First call should succeed
		_, err = fake.InvokePing(ctx, conn)
		require.NoError(t, err)

		// Update the server certificate
		serverFs.Save(secondCA, secondServerKeyPair)
		time.Sleep(1 * time.Second)

		// New connection should fail
		newConn, err := grpc.NewClient(
			serverName,
			grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
				return lis.Dial()
			}),
			grpc.WithTransportCredentials(clientLoader.GRPCCredentials()),
		)
		require.NoError(t, err)
		defer newConn.Close()
		_, err = fake.InvokePing(ctx, newConn)
		require.Error(t, err)

		// Active connection should ok
		_, err = fake.InvokePing(ctx, conn)
		require.NoError(t, err)

		// Update the client certificate
		clientFs.Save(secondCA, secondClientKeyPair)
		time.Sleep(1 * time.Second)

		// New connection should ok for the new certificate
		newConn, err = grpc.NewClient(
			secondServerName,
			grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
				return lis.Dial()
			}),
			grpc.WithTransportCredentials(clientLoader.GRPCCredentials()),
		)
		require.NoError(t, err)
		defer newConn.Close()

		// Third call should succeed
		_, err = fake.InvokePing(ctx, newConn)
		require.NoError(t, err)

		// Active connection should be kept alive
		_, err = fake.InvokePing(ctx, conn)
		require.NoError(t, err)

		server.GracefulStop()
		cancel()
		require.NoError(t, <-grpcErrCh)
		require.NoError(t, <-svrErrCh)
		require.NoError(t, <-cliErrCh)
	})
}
