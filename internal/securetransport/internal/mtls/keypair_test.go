package mtls

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTLSKeyPair_Parse(t *testing.T) {
	t.Parallel()

	var (
		ca      = fakeCA(fakeCATemplate())
		keyPair = ca.Sign(fakeServerTemplate())
	)

	tests := []struct {
		Name        string
		Raw         *TLSKeyPairRaw
		Expected    *TLSKeyPair
		ExpectedErr error
	}{
		{
			Name: "invalid CA",
			Raw: NewTLSKeyPairRaw(
				[]byte("invalid CA"),
				ToCertificatePEM(keyPair.Certificate.Leaf.Raw),
				ToPrivateKeyPEM(keyPair.Certificate.PrivateKey),
			),
			ExpectedErr: ErrAppendCACertsFromPEM,
		},
		{
			Name: "invalid certificate",
			Raw: NewTLSKeyPairRaw(
				ToCertificatePEM(ca.Certificate.Raw),
				[]byte("invalid certificate"),
				ToPrivateKeyPEM(keyPair.Certificate.PrivateKey),
			),
			ExpectedErr: ErrLoadCertificateAndKeyFromLocalFile,
		},
		{
			Name: "valid key pair",
			Raw: NewTLSKeyPairRaw(
				ToCertificatePEM(ca.Certificate.Raw),
				ToCertificatePEM(keyPair.Certificate.Leaf.Raw),
				ToPrivateKeyPEM(keyPair.Certificate.PrivateKey),
			),
			Expected: keyPair,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			parsedKeyPair, err := tt.Raw.Parse()
			if tt.ExpectedErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tt.ExpectedErr)
			} else {
				require.NoError(t, err)
				require.True(t, parsedKeyPair.Equal(tt.Expected))
			}
		})
	}
}
