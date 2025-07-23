package keypair

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"
)

type Bundle struct {
	opts      Options
	bundleMap bundleMap
}

func NewBundle(opts Options) (*Bundle, error) {
	rv := &Bundle{
		opts:      opts,
		bundleMap: bundleMap{},
	}

	if err := rv.load(); err != nil {
		return nil, err
	}

	return rv, nil
}

func (b *Bundle) CAPool() *x509.CertPool {
	caPool, ok := b.bundleMap.GetCAPool()
	if !ok {
		panic("CAPool not found")
	}
	return caPool
}

func (b *Bundle) KeyPairs() []tls.Certificate {
	keyPairs, ok := b.bundleMap.GetKeyPairs()
	if !ok {
		panic("KeyPairs not found")
	}
	return keyPairs
}

func (b *Bundle) StartReloadLoop(ctx context.Context) {
	ticker := time.NewTicker(b.opts.ReloadInterval)
	defer ticker.Stop()
	defer slog.Info("Reload loop stopped")

	for {
		select {
		case <-ticker.C:
			if err := b.load(); err != nil {
				slog.Error("Failed to reload bundle", "error", err)
			}
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
				Roots: b.CAPool(),
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
			return &b.KeyPairs()[0], nil
		},
	}
}

func (b *Bundle) CreateTLSConfigForServer() *tls.Config {
	return &tls.Config{
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			slog.Info("Getting config for client", slog.String("server_name", info.ServerName))
			return &tls.Config{
				Certificates: b.KeyPairs(),
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    b.CAPool(),
			}, nil
		},
	}
}

func (b *Bundle) createCAPool() (*x509.CertPool, error) {
	var caCertPEMs [][]byte
	for _, ca := range b.opts.CertificateAuthorities {
		pem, err := os.ReadFile(ca)
		if err != nil {
			return nil, err
		}
		caCertPEMs = append(caCertPEMs, pem)
	}

	existing, found := b.bundleMap.GetCAPEMs()
	if found && PEMsEqual(existing, caCertPEMs) {
		caPool, _ := b.bundleMap.GetCAPool()
		return caPool, nil
	}

	slog.Info("Creating new CA pool")
	caPool := x509.NewCertPool()
	for _, pem := range caCertPEMs {
		caPool.AppendCertsFromPEM(pem)
	}

	b.bundleMap.StoreCAPool(caPool)
	b.bundleMap.StoreCAPEMs(caCertPEMs)
	return caPool, nil
}

func (b *Bundle) createKeyPairs() ([]tls.Certificate, error) {
	var rawKeyPairs []RawKeyPair
	for _, keyPair := range b.opts.KeyPairs {
		parts := strings.Split(keyPair, ":")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid key pair format: %s", keyPair)
		}
		cert, err := os.ReadFile(parts[0])
		if err != nil {
			return nil, err
		}
		key, err := os.ReadFile(parts[1])
		if err != nil {
			return nil, err
		}
		rawKeyPairs = append(rawKeyPairs, RawKeyPair{
			cert: cert,
			key:  key,
		})
	}

	existing, found := b.bundleMap.GetRawKeyPairs()
	if found && RawKeyPairsEqual(existing, rawKeyPairs) {
		keyPairs, _ := b.bundleMap.GetKeyPairs()
		return keyPairs, nil
	}

	slog.Info("Creating new key pairs")
	keyPairs := make([]tls.Certificate, 0, len(rawKeyPairs))
	for _, rawKeyPair := range rawKeyPairs {
		keyPair, err := tls.X509KeyPair(rawKeyPair.cert, rawKeyPair.key)
		if err != nil {
			return nil, err
		}
		keyPairs = append(keyPairs, keyPair)
	}

	b.bundleMap.StoreKeyPairs(keyPairs)
	b.bundleMap.StoreRawKeyPairs(rawKeyPairs)
	return keyPairs, nil
}

func (b *Bundle) load() error {
	t1 := time.Now()
	defer func() {
		elapsed := time.Since(t1)
		if elapsed > 1*time.Millisecond {
			slog.Info("Loaded bundles", slog.Duration("duration", elapsed))
		}
	}()

	_, err := b.createCAPool()
	if err != nil {
		return err
	}
	_, err = b.createKeyPairs()
	if err != nil {
		return err
	}
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
