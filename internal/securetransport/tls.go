package securetransport

import (
	"context"
	"crypto/tls"
	"net/http"

	"google.golang.org/grpc/credentials"

	"github.com/zarvd/mtls-demo/internal/securetransport/internal/mtls"
)

// ClientTLSConfigLoader provides an interface for loading and managing TLS configurations
// for client connections. It supports dynamic certificate reloading without dropping
// active connections, ensuring seamless certificate rotation and high availability.
type ClientTLSLoader interface {
	// StartLoop begins the certificate monitoring and rotation loop.
	// It should run until the provided context is cancelled.
	StartLoop(ctx context.Context) error
	// HTTPRoundTripper returns an HTTP round tripper with dynamic TLS configuration.
	HTTPRoundTripper() http.RoundTripper
	// GRPCCredentials returns gRPC transport credentials with dynamic TLS configuration.
	GRPCCredentials() credentials.TransportCredentials
}

// ServerTLSConfigLoader provides an interface for loading and managing TLS configurations
// for server connections. It supports dynamic certificate reloading without dropping
// active connections, ensuring seamless certificate rotation and high availability.
type ServerTLSLoader interface {
	// StartLoop begins the certificate monitoring and rotation loop.
	// It should run until the provided context is cancelled.
	StartLoop(ctx context.Context) error
	// ServerTLSConfig returns the current TLS configuration for server connections.
	// The configuration is automatically updated when certificates are reloaded.
	ServerTLSConfig() *tls.Config
}

type LocalFileTLSConfigLoaderOptions = mtls.LocalFileTLSConfigLoaderOptions

// NewLocalFileClientTLSConfigLoader creates a ClientTLSConfigLoader that
// loads TLS certificates from local files with automatic reloading.
func NewLocalFileClientTLSConfigLoader(options LocalFileTLSConfigLoaderOptions) (ClientTLSLoader, error) {
	return mtls.NewLocalFileClientTLSConfigLoader(options)
}

// NewLocalFileServerTLSConfigLoader creates a ServerTLSConfigLoader that
// loads TLS certificates from local files with automatic reloading.
func NewLocalFileServerTLSConfigLoader(options LocalFileTLSConfigLoaderOptions) (ServerTLSLoader, error) {
	return mtls.NewLocalFileServerTLSConfigLoader(options)
}
