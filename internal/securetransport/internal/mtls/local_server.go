package mtls

import (
	"context"
	"crypto/tls"
)

type LocalFileServerTLSConfigLoader struct {
	loader *LocalFileTLSConfigLoader
}

func NewLocalFileServerTLSConfigLoader(options LocalFileTLSConfigLoaderOptions) (*LocalFileServerTLSConfigLoader, error) {
	if options.Validate == nil {
		options.Validate = ValidateKeyPairForServerUsage
	}
	loader, err := NewLocalFileTLSConfigLoader(options)
	if err != nil {
		return nil, err
	}
	return &LocalFileServerTLSConfigLoader{loader: loader}, nil
}

func (l *LocalFileServerTLSConfigLoader) StartLoop(ctx context.Context) error {
	return l.loader.StartLoop(ctx)
}

func (l *LocalFileServerTLSConfigLoader) ServerTLSConfig() *tls.Config {
	return CreateTLSConfigForServer(l.loader)
}
