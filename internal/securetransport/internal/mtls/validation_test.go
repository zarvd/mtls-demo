package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateKeyPair(t *testing.T) {
	t.Parallel()

	t.Run("it should return an error if the certificate is nil", func(t *testing.T) {
		t.Parallel()

		err := validateKeyPair(&TLSKeyPair{Certificate: nil})
		require.Error(t, err)
		assert.ErrorContains(t, err, "certificate is nil")
	})

	t.Run("it should return an error if the CA pool is nil", func(t *testing.T) {
		t.Parallel()

		err := validateKeyPair(&TLSKeyPair{Certificate: &tls.Certificate{}})
		require.Error(t, err)
		assert.ErrorContains(t, err, "CA pool is nil")
	})

	t.Run("it should return an error if the certificate is not valid yet", func(t *testing.T) {
		t.Parallel()

		ca := fakeCA(fakeCATemplate())
		keyPair := ca.Sign(fakeClientTemplate(func(cert *x509.Certificate) {
			cert.NotBefore = time.Now().Add(1 * time.Hour)
		}))

		err := validateKeyPair(keyPair)
		require.Error(t, err)
		assert.ErrorContains(t, err, "certificate is not valid yet")
	})

	t.Run("it should return an error if the certificate will expire in less than 10 minutes", func(t *testing.T) {
		t.Parallel()

		ca := fakeCA(fakeCATemplate())
		keyPair := ca.Sign(fakeClientTemplate(func(cert *x509.Certificate) {
			cert.NotAfter = time.Now().Add(1 * time.Minute)
		}))

		err := validateKeyPair(keyPair)
		require.Error(t, err)
		assert.ErrorContains(t, err, "certificate will expire in less than")
	})
}

func TestValidateKeyPairForServerUsage(t *testing.T) {
	t.Parallel()

	t.Run("it should return an error if the certificate is nil", func(t *testing.T) {
		t.Parallel()

		err := ValidateKeyPairForServerUsage(&TLSKeyPair{Certificate: nil})
		require.Error(t, err)
		assert.ErrorContains(t, err, "certificate is nil")
	})

	t.Run("it should return an error if the certificate is not valid for server usage", func(t *testing.T) {
		t.Parallel()

		keyPair := fakeCA(fakeCATemplate()).Sign(fakeClientTemplate())
		err := ValidateKeyPairForServerUsage(keyPair)
		require.Error(t, err)
		assert.ErrorContains(t, err, "certificate is not valid for server usage")
	})

	t.Run("it should return an error if the certificate is not signed by the CA", func(t *testing.T) {
		t.Parallel()

		ca := fakeCA(fakeCATemplate())
		keyPair := ca.Sign(fakeServerTemplate())
		keyPair.CAs = fakeCA(fakeCATemplate()).pool()
		err := ValidateKeyPairForServerUsage(keyPair)
		require.Error(t, err)
		assert.ErrorContains(t, err, "verify certificate signature")
	})

	t.Run("it should return nil if the certificate is valid for server usage", func(t *testing.T) {
		t.Parallel()

		keyPair := fakeCA(fakeCATemplate()).Sign(fakeServerTemplate())
		err := ValidateKeyPairForServerUsage(keyPair)
		require.NoError(t, err)
	})
}

func TestValidateKeyPairForClientUsage(t *testing.T) {
	t.Parallel()

	t.Run("it should return an error if the certificate is nil", func(t *testing.T) {
		t.Parallel()

		err := ValidateKeyPairForClientUsage(&TLSKeyPair{Certificate: nil})
		require.Error(t, err)
		assert.ErrorContains(t, err, "certificate is nil")
	})

	t.Run("it should return an error if the certificate is not valid for client usage", func(t *testing.T) {
		t.Parallel()

		keyPair := fakeCA(fakeCATemplate()).Sign(fakeServerTemplate())
		err := ValidateKeyPairForClientUsage(keyPair)
		require.Error(t, err)
		assert.ErrorContains(t, err, "certificate is not valid for client usage")
	})

	t.Run("it should return an error if the certificate is not signed by the CA", func(t *testing.T) {
		t.Parallel()

		ca := fakeCA(fakeCATemplate())
		keyPair := ca.Sign(fakeClientTemplate())
		keyPair.CAs = fakeCA(fakeCATemplate()).pool()
		err := ValidateKeyPairForClientUsage(keyPair)
		require.Error(t, err)
		assert.ErrorContains(t, err, "verify certificate signature")
	})

	t.Run("it should return nil if the certificate is valid for client usage", func(t *testing.T) {
		t.Parallel()

		keyPair := fakeCA(fakeCATemplate()).Sign(fakeClientTemplate())
		err := ValidateKeyPairForClientUsage(keyPair)
		require.NoError(t, err)
	})
}
