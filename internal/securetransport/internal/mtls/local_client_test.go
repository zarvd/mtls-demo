package mtls

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLocalFileClientTLSConfigLoader(t *testing.T) {
	t.Parallel()

	t.Run("it should load the certificate and key from the files", func(t *testing.T) {
		t.Parallel()

		fs := MustTempKeyPairFiles()
		defer fs.Close()

		ca := fakeCA(fakeCATemplate())
		keyPair := ca.Sign(fakeClientTemplate())

		fs.SaveCA(ca)
		fs.SaveCertificate(keyPair.Certificate)
		fs.SaveKey(keyPair.Certificate.PrivateKey)

		loader, err := NewLocalFileClientTLSConfigLoader(LocalFileTLSConfigLoaderOptions{
			CABundle:       fs.CA.Name(),
			Certificate:    fs.Certificate.Name(),
			Key:            fs.Key.Name(),
			ReloadInterval: 500 * time.Millisecond,
		})
		require.NoError(t, err)
		require.NotNil(t, loader)

		loadedKeyPair := loader.loader.KeyPair()
		require.NotNil(t, loadedKeyPair)
		assert.True(t, loadedKeyPair.Equal(keyPair))

		require.NotNil(t, loader.HTTPRoundTripper())
		require.NotNil(t, loader.GRPCCredentials())
	})

	t.Run("it should return an error if the certificate is not valid for client usage", func(t *testing.T) {
		t.Parallel()

		fs := MustTempKeyPairFiles()
		defer fs.Close()

		ca := fakeCA(fakeCATemplate())
		keyPair := ca.Sign(fakeServerTemplate())

		fs.SaveCA(ca)
		fs.SaveCertificate(keyPair.Certificate)
		fs.SaveKey(keyPair.Certificate.PrivateKey)

		_, err := NewLocalFileClientTLSConfigLoader(LocalFileTLSConfigLoaderOptions{
			CABundle:       fs.CA.Name(),
			Certificate:    fs.Certificate.Name(),
			Key:            fs.Key.Name(),
			ReloadInterval: 500 * time.Millisecond,
		})
		require.Error(t, err)
		assert.ErrorContains(t, err, "certificate is not valid for client usage")
	})
}
