package keypair

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

type Bundle struct {
	opts Options

	mu      sync.RWMutex
	keyPair *KeyPair
}

func NewBundle(opts Options) (*Bundle, error) {
	rv := &Bundle{
		opts: opts,
	}

	if err := rv.load(); err != nil {
		return nil, err
	}

	return rv, nil
}

func (b *Bundle) KeyPair() *KeyPair {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return b.keyPair
}

func (b *Bundle) StartReloadLoop(ctx context.Context) {
	defer slog.Info("Reload loop stopped")

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		slog.Error("Failed to create fsnotify watcher", "error", err)
		return
	}
	defer watcher.Close()

	for _, path := range b.opts.ListFilePaths() {
		watcher.Add(path)
	}

	for {
		select {
		case event := <-watcher.Events: // TODO: deduplicate events
			slog.Info("Certificate changed", "event", event)
			if err := b.load(); err != nil {
				slog.Error("Failed to reload bundle", "error", err)
			}
		case err := <-watcher.Errors:
			slog.Error("File watcher error", "error", err)
		case <-ctx.Done():
			return
		}
	}
}

func (b *Bundle) CreateTLSConfigForClient() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, // Enable custom certificate verification
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			slog.Info("Verifying peer certificate")
			certs := make([]*x509.Certificate, 0, len(rawCerts))
			for _, rawCert := range rawCerts {
				cert, err := x509.ParseCertificate(rawCert)
				if err != nil {
					return fmt.Errorf("custom verify peer certificate: %w", err)
				}
				certs = append(certs, cert)
			}
			opts := x509.VerifyOptions{
				Roots: b.KeyPair().CAPool,
			}
			for _, cert := range certs[1:] {
				opts.Intermediates.AddCert(cert)
			}
			if _, err := certs[0].Verify(opts); err != nil {
				return fmt.Errorf("custom verify peer certificate: %w", err)
			}
			return nil
		},
		GetClientCertificate: func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			slog.Info("Getting client certificate")
			keyPair := b.KeyPair()
			return keyPair.Certificate, nil
		},
	}
}

func (b *Bundle) CreateTLSConfigForServer() *tls.Config {
	return &tls.Config{
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			slog.Info("Getting config for client", slog.String("server_name", info.ServerName))
			keyPair := b.KeyPair()
			return &tls.Config{
				ClientAuth: tls.RequireAndVerifyClientCert,
				ClientCAs:  keyPair.CAPool,
				GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
					return keyPair.Certificate, nil
				},
			}, nil
		},
	}
}

func (b *Bundle) load() error {
	t1 := time.Now()
	defer func() {
		elapsed := time.Since(t1)
		if elapsed > 1*time.Millisecond {
			slog.Info("Loaded bundles", slog.Duration("duration", elapsed))
		}
	}()

	caBundle, err := os.ReadFile(b.opts.CABundle)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(b.opts.Certificate, b.opts.Key)
	if err != nil {
		return err
	}

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caBundle)

	keyPair := &KeyPair{
		Certificate: &cert,
		CAPool:      caPool,
	}

	b.mu.Lock()
	b.keyPair = keyPair
	b.mu.Unlock()

	return nil
}

func PEMsEqual(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}

	return true
}
