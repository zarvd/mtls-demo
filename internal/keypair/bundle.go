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

	watchChanges := func() {
		const MaxRetries = 3
		for _, path := range b.opts.ListFilePaths() {
			watched := false
			for range MaxRetries {
				err := watcher.Add(path)
				if err == nil {
					watched = true
					break
				}
				slog.Error("Failed to watch file", "path", path, "error", err)
				time.Sleep(time.Second)
			}
			if !watched {
				panic(fmt.Sprintf("Failed to watch file: %s", path))
			}
		}
	}

	watchChanges()
	for {
		select {
		case <-watcher.Events: // TODO: deduplicate events
			time.Sleep(time.Second) // Just wait a bit to avoid partial changes
			if err := b.load(); err != nil {
				slog.Error("Failed to reload bundle", "error", err)
			}
			watchChanges()
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
			certs := make([]*x509.Certificate, 0, len(rawCerts))
			for i, rawCert := range rawCerts {
				cert, err := x509.ParseCertificate(rawCert)
				if err != nil {
					return fmt.Errorf("parse peer certificate: %w", err)
				}
				certs = append(certs, cert)
				slog.Info("Parsed peer certificate",
					slog.Int("index", i),
					slog.String("subject", cert.Subject.CommonName),
					slog.String("issuer", cert.Issuer.CommonName),
				)
			}

			keyPair := b.KeyPair()
			rootPool := keyPair.CAPool
			intermediatePool := x509.NewCertPool()
			for _, cert := range certs[1:] {
				intermediatePool.AddCert(cert)
			}

			opts := x509.VerifyOptions{
				Roots:         rootPool,
				Intermediates: intermediatePool,
			}
			if _, err := certs[0].Verify(opts); err != nil {
				slog.Error("Failed to verify peer certificate",
					slog.String("error", err.Error()),
					slog.String("key-pair", keyPair.String()),
					slog.String("peer-cert-subject", certs[0].Subject.CommonName),
					slog.String("peer-cert-issuer", certs[0].Issuer.CommonName),
				)
				return fmt.Errorf("verify peer certificate: %w", err)
			}
			return nil
		},
		GetClientCertificate: func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			keyPair := b.KeyPair()
			return keyPair.Certificate, nil
		},
	}
}

func (b *Bundle) CreateTLSConfigForServer() *tls.Config {
	return &tls.Config{
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
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
		slog.Info("Loaded key pair", slog.Duration("duration", time.Since(t1)))
	}()

	caBundle, err := os.ReadFile(b.opts.CABundle)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(b.opts.Certificate, b.opts.Key)
	if err != nil {
		return err
	}

	keyPair, err := NewKeyPair(&cert, caBundle)
	if err != nil {
		return err
	}

	b.mu.Lock()
	b.keyPair = keyPair
	b.mu.Unlock()

	slog.Info("Loaded key pair", slog.String("key-pair", keyPair.String()))

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
