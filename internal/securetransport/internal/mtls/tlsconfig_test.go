package mtls

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateTLSConfigForServer(t *testing.T) {
	t.Parallel()

	t.Run("it should return a valid TLS config for server", func(t *testing.T) {
		t.Parallel()
		var (
			ca      = fakeCA(fakeCATemplate())
			keyPair = ca.Sign(fakeServerTemplate())
			loader  = &fakeKeyPairLoader{keyPair: keyPair}
			config  = CreateTLSConfigForServer(loader)
		)
		require.NotNil(t, config)
		assert.NotNil(t, config.GetConfigForClient)
	})
}
