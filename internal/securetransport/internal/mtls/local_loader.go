package mtls

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"time"
)

var DefaultReloadInterval = 10 * time.Second

type LocalFileTLSConfigLoaderOptions struct {
	CABundle       string                          // Path to the CA bundle PEM file
	Certificate    string                          // Path to the certificate PEM file
	Key            string                          // Path to the key PEM file
	ReloadInterval time.Duration                   // Interval to reload the TLS config
	Validate       func(keyPair *TLSKeyPair) error // Validate the key pair after loading
}

func (opts *LocalFileTLSConfigLoaderOptions) defaults() error {
	if file, err := os.Stat(opts.CABundle); err != nil || file.IsDir() {
		return fmt.Errorf("check CA bundle file: %w", err)
	}
	if file, err := os.Stat(opts.Certificate); err != nil || file.IsDir() {
		return fmt.Errorf("check certificate file: %w", err)
	}
	if file, err := os.Stat(opts.Key); err != nil || file.IsDir() {
		return fmt.Errorf("check key file: %w", err)
	}
	if opts.ReloadInterval == 0 {
		opts.ReloadInterval = DefaultReloadInterval
	}
	if opts.Validate == nil {
		return fmt.Errorf("validate function is nil")
	}
	return nil
}

type LocalFileTLSConfigLoader struct {
	options LocalFileTLSConfigLoaderOptions
	keyPair atomic.Pointer[TLSKeyPair]
}

func NewLocalFileTLSConfigLoader(options LocalFileTLSConfigLoaderOptions) (*LocalFileTLSConfigLoader, error) {
	if err := options.defaults(); err != nil {
		return nil, err
	}
	loader := &LocalFileTLSConfigLoader{options: options}
	if err := loader.loadKeyPair(); err != nil {
		return nil, err
	}
	return loader, nil
}

func (l *LocalFileTLSConfigLoader) StartLoop(ctx context.Context) error {
	ticker := time.NewTicker(l.options.ReloadInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := l.loadKeyPair(); err != nil {
				// TODO: log error but continue to watch for changes
			}
		}
	}
}

func (l *LocalFileTLSConfigLoader) KeyPair() *TLSKeyPair {
	return l.keyPair.Load()
}

func (l *LocalFileTLSConfigLoader) loadKeyPair() error {
	nextRaw, err := l.readKeyPairRaw()
	if err != nil {
		return err
	}
	if l.keyPair.Load() != nil && l.keyPair.Load().Raw.Equal(nextRaw) {
		return nil // No changes, skip loading.
	}
	keyPair, err := nextRaw.Parse()
	if err != nil {
		return fmt.Errorf("parse key pair: %w", err)
	}
	if err := l.options.Validate(keyPair); err != nil {
		return fmt.Errorf("validate key pair: %w", err)
	}
	l.keyPair.Store(keyPair)
	return nil
}

func (l *LocalFileTLSConfigLoader) readKeyPairRaw() (*TLSKeyPairRaw, error) {
	bundlePEM, err := os.ReadFile(l.options.CABundle)
	if err != nil {
		return nil, fmt.Errorf("read CA bundle from local file: %w", err)
	}
	certPEM, err := os.ReadFile(l.options.Certificate)
	if err != nil {
		return nil, fmt.Errorf("read certificate from local file: %w", err)
	}
	keyPEM, err := os.ReadFile(l.options.Key)
	if err != nil {
		return nil, fmt.Errorf("read key from local file: %w", err)
	}
	return &TLSKeyPairRaw{
		caBytes:   bundlePEM,
		certBytes: certPEM,
		keyBytes:  keyPEM,
	}, nil
}
