package securetransport

import (
	"context"
	"crypto/tls"
	"net/http"

	"github.com/zarvd/mtls-demo/internal/securetransport/internal/mtls"
	"google.golang.org/grpc/credentials"
)

// ClientTLSConfigLoader provides an interface for loading and managing TLS configurations
// for client connections. It supports dynamic certificate reloading without dropping
// active connections, ensuring seamless certificate rotation and high availability.
type ClientTLSLoader interface {
	// StartLoop begins the certificate monitoring and rotation loop.
	// It should run until the provided context is cancelled.
	StartLoop(ctx context.Context) error

	HTTPRoundTripper() http.RoundTripper
	GRPCCredentials() credentials.TransportCredentials
}

// ServerTLSConfigLoader provides an interface for loading and managing TLS configurations
// for server connections. It supports dynamic certificate reloading without dropping
// active connections, ensuring seamless certificate rotation and high availability.
type ServerTLSLoader interface {
	// StartLoop begins the certificate monitoring and rotation loop.
	// It should run until the provided context is cancelled.
	StartLoop(ctx context.Context) error

	// TLSConfig returns the current TLS configuration for server connections.
	// The returned configuration is dynamically updated when certificates are
	// automatically reloaded. If a reloaded certificate fails validation,
	// the loader will retain the last valid configuration to ensure service continuity
	// until a new valid certificate becomes available.
	TLSConfig() (*tls.Config, error)
}

// LocalFileTLSConfigLoaderOptions defines the configuration options for
// loading TLS certificates from local files.
type LocalFileTLSConfigLoaderOptions = mtls.LocalFileTLSConfigLoaderOptions

// NewLocalFileClientTLSConfigLoader creates a new ClientTLSConfigLoader that
// loads TLS certificates from local files. The loader monitors the certificate
// files for changes and automatically reloads them when modified.
//
// The options parameter specifies the paths to the CA bundle, certificate,
// and private key files, along with the reload interval and validation function.
// If no validation function is provided, it defaults to client-specific validation.
func NewLocalFileClientTLSConfigLoader(options LocalFileTLSConfigLoaderOptions) (ClientTLSLoader, error) {
	return mtls.NewLocalFileClientTLSConfigLoader(options)
}

// NewLocalFileServerTLSConfigLoader creates a new ServerTLSConfigLoader that
// loads TLS certificates from local files. The loader monitors the certificate
// files for changes and automatically reloads them when modified.
//
// The options parameter specifies the paths to the CA bundle, certificate,
// and private key files, along with the reload interval and validation function.
// If no validation function is provided, it defaults to server-specific validation.
func NewLocalFileServerTLSConfigLoader(options LocalFileTLSConfigLoaderOptions) (ServerTLSLoader, error) {
	return mtls.NewLocalFileServerTLSConfigLoader(options)
}
