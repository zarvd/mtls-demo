package keypair

import (
	"time"
)

type Options struct {
	CertificateAuthorities []string      `required:"" type:"existingfile" help:"Path to the certificate authority file"`
	KeyPairs               []string      `required:"" help:"Key pair files in format cert:key (e.g., server.crt:server.key)"`
	ReloadInterval         time.Duration `default:"10s" help:"Interval to reload the certificate and key"`
}
