package mtls

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLocalFileTLSConfigLoader(t *testing.T) {
	t.Parallel()

	const (
		TempFilePrefix = "securetransport-tls-test"
	)

	t.Run("it should return an error if the certificate files cannot be read", func(t *testing.T) {
		t.Parallel()

		_, err := NewLocalFileTLSConfigLoader(LocalFileTLSConfigLoaderOptions{
			CABundle:    "testdata/invalid.pem",
			Certificate: "testdata/invalid.pem",
			Key:         "testdata/invalid.pem",
		})
		require.Error(t, err)
		assert.ErrorContains(t, err, "check CA bundle file")
	})

	t.Run("it should load certificate from file", func(t *testing.T) {
		t.Parallel()
		fs := MustTempKeyPairFiles()
		defer fs.Close()

		var (
			ca      = fakeCA(fakeCATemplate())
			keyPair = ca.Sign(fakeServerTemplate())
		)

		fs.SaveCA(ca)
		fs.SaveCertificate(keyPair.Certificate)
		fs.SaveKey(keyPair.Certificate.PrivateKey)

		loader, err := NewLocalFileTLSConfigLoader(LocalFileTLSConfigLoaderOptions{
			CABundle:       fs.CA.Name(),
			Certificate:    fs.Certificate.Name(),
			Key:            fs.Key.Name(),
			ReloadInterval: 500 * time.Millisecond,
			Validate:       ValidateKeyPairForServerUsage,
		})
		require.NoError(t, err)
		loadedKeyPair := loader.KeyPair()
		require.NotNil(t, loadedKeyPair)
		assert.Equal(t, keyPair.Certificate.Leaf.Subject.CommonName, loadedKeyPair.Certificate.Leaf.Subject.CommonName)
	})
}

func TestLocalFileTLSConfigLoader_StartLoop(t *testing.T) {
	t.Parallel()

	t.Run("it should reload certificate when file is changed", func(t *testing.T) {
		t.Parallel()
		fs := MustTempKeyPairFiles()
		defer fs.Close()

		const (
			FirstKeyPairName  = "first-key-pair"
			SecondKeyPairName = "second-key-pair"
		)
		var (
			ca      = fakeCA(fakeCATemplate())
			keyPair = ca.Sign(fakeServerTemplate(func(template *x509.Certificate) {
				template.Subject.CommonName = FirstKeyPairName
			}))
		)

		fs.SaveCA(ca)
		fs.SaveCertificate(keyPair.Certificate)
		fs.SaveKey(keyPair.Certificate.PrivateKey)

		loader, err := NewLocalFileTLSConfigLoader(LocalFileTLSConfigLoaderOptions{
			CABundle:       fs.CA.Name(),
			Certificate:    fs.Certificate.Name(),
			Key:            fs.Key.Name(),
			ReloadInterval: 500 * time.Millisecond,
			Validate:       ValidateKeyPairForServerUsage,
		})
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		errC := make(chan error, 1)
		go func() {
			errC <- loader.StartLoop(ctx)
		}()

		assert.Equal(t,
			keyPair.Certificate.Leaf.Subject.CommonName,
			loader.KeyPair().Certificate.Leaf.Subject.CommonName,
		)
		assert.Equal(t,
			FirstKeyPairName,
			loader.KeyPair().Certificate.Leaf.Subject.CommonName,
		)

		newKeyPair := ca.Sign(fakeServerTemplate(func(template *x509.Certificate) {
			template.Subject.CommonName = SecondKeyPairName
		}))
		fs.SaveCertificate(newKeyPair.Certificate)
		fs.SaveKey(newKeyPair.Certificate.PrivateKey)

		time.Sleep(1 * time.Second)

		assert.Equal(t,
			newKeyPair.Certificate.Leaf.Subject.CommonName,
			loader.KeyPair().Certificate.Leaf.Subject.CommonName,
		)
		assert.Equal(t,
			SecondKeyPairName,
			loader.KeyPair().Certificate.Leaf.Subject.CommonName,
		)

		cancel()
		require.NoError(t, <-errC)
	})
}
