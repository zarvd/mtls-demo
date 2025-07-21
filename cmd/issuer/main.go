package main

import (
	"crypto/x509/pkix"
	"log"

	"github.com/alecthomas/kong"
)

type CLI struct {
}

func main() {
	cli := new(CLI)
	cliCtx := kong.Parse(cli)

	const (
		Country    = "CN"
		Province   = "Guangdong"
		City       = "Shenzhen"
		CommonName = "CA"
		Email      = "mtls-ca@zarvd.dev"
	)

	ca, err := makeCertificateAuthority(pkix.Name{
		Country:    []string{Country},
		Province:   []string{Province},
		Locality:   []string{City},
		CommonName: "mtls-ca",
	})
	if err != nil {
		log.Fatalf("Failed to make CA: %v", err)
	}

	server, err := makeServerCertificate(ca, pkix.Name{
		Country:    []string{Country},
		Province:   []string{Province},
		Locality:   []string{City},
		CommonName: "mtls-server",
	}, []string{"mtls-server.zarvd.dev"})
	if err != nil {
		log.Fatalf("Failed to make server: %v", err)
	}

	client, err := makeClientCertificate(ca, pkix.Name{
		Country:    []string{Country},
		Province:   []string{Province},
		Locality:   []string{City},
		CommonName: "mtls-client",
	}, []string{"mtls-client.zarvd.dev"})
	if err != nil {
		log.Fatalf("Failed to make client: %v", err)
	}

	cliCtx.FatalIfErrorf(ca.SaveCertificate("certs/ca.crt"))
	cliCtx.FatalIfErrorf(ca.SavePrivateKey("certs/ca.key"))

	cliCtx.FatalIfErrorf(server.SaveCertificate("certs/server.crt"))
	cliCtx.FatalIfErrorf(server.SavePrivateKey("certs/server.key"))

	cliCtx.FatalIfErrorf(client.SaveCertificate("certs/client.crt"))
	cliCtx.FatalIfErrorf(client.SavePrivateKey("certs/client.key"))
}
