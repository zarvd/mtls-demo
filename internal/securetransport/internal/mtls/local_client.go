package mtls

import (
	"context"
	"net/http"

	"google.golang.org/grpc/credentials"
)

type LocalFileClientTLSConfigLoader struct {
	loader *LocalFileTLSConfigLoader
}

func NewLocalFileClientTLSConfigLoader(options LocalFileTLSConfigLoaderOptions) (*LocalFileClientTLSConfigLoader, error) {
	if options.Validate == nil {
		options.Validate = ValidateKeyPairForClientUsage
	}
	loader, err := NewLocalFileTLSConfigLoader(options)
	if err != nil {
		return nil, err
	}
	return &LocalFileClientTLSConfigLoader{loader: loader}, nil
}

func (l *LocalFileClientTLSConfigLoader) StartLoop(ctx context.Context) error {
	return l.loader.StartLoop(ctx)
}

func (l *LocalFileClientTLSConfigLoader) HTTPRoundTripper() http.RoundTripper {
	return CreateDynamicTLSTransport(l.loader)
}

func (l *LocalFileClientTLSConfigLoader) GRPCCredentials() credentials.TransportCredentials {
	return CreateDynamicTLSCredentials(l.loader)
}
