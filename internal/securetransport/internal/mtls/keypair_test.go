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
			Raw: &TLSKeyPairRaw{
				caBytes: []byte("invalid CA"),
			},
			ExpectedErr: ErrAppendCACertsFromPEM,
		},
		{
			Name: "invalid certificate",
			Raw: &TLSKeyPairRaw{
				caBytes:   ToCertificatePEM(ca.Certificate.Raw),
				certBytes: []byte("invalid certificate"),
			},
			ExpectedErr: ErrLoadCertificateAndKeyFromLocalFile,
		},
		{
			Name: "valid key pair",
			Raw: &TLSKeyPairRaw{
				caBytes:   ToCertificatePEM(ca.Certificate.Raw),
				certBytes: ToCertificatePEM(keyPair.Certificate.Leaf.Raw),
				keyBytes:  ToPrivateKeyPEM(keyPair.Certificate.PrivateKey),
			},
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
