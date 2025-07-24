package main

import (
	"github.com/alecthomas/kong"
)

type Action string

const (
	ActionNew          = "new"
	ActionRotateCA     = "rotate-ca"
	ActionRotateServer = "rotate-server"
	ActionRotateClient = "rotate-client"
)

type CLI struct {
	Action Action `arg:"" required:"" enum:"new,rotate-ca,rotate-server,rotate-client" help:"Action to perform"`
}

const (
	CABundlePath   = "certs/ca-bundle.crt"
	CACertPath     = "certs/ca.crt"
	CAKeyPath      = "certs/ca.key"
	ServerCertPath = "certs/server/tls.crt"
	ServerKeyPath  = "certs/server/tls.key"
	ClientCertPath = "certs/client/tls.crt"
	ClientKeyPath  = "certs/client/tls.key"
)

func main() {
	cli := new(CLI)
	cliCtx := kong.Parse(cli)

	switch cli.Action {
	case ActionNew:
		ca := mustMakeCA()
		server := mustMakeServerCertificate(ca)
		client := mustMakeClientCertificate(ca)

		cliCtx.FatalIfErrorf(ca.SaveBundleWith([]*KeyPair{}, CABundlePath))
		cliCtx.FatalIfErrorf(ca.SaveCertificate(CACertPath))
		cliCtx.FatalIfErrorf(ca.SavePrivateKey(CAKeyPath))
		cliCtx.FatalIfErrorf(server.SaveCertificate(ServerCertPath))
		cliCtx.FatalIfErrorf(server.SavePrivateKey(ServerKeyPath))
		cliCtx.FatalIfErrorf(client.SaveCertificate(ClientCertPath))
		cliCtx.FatalIfErrorf(client.SavePrivateKey(ClientKeyPath))
	case ActionRotateCA:
		newCA := mustMakeCA()
		oldCA, err := loadCertificateAuthority(CACertPath, CAKeyPath)
		if err != nil {
			cliCtx.Fatalf("Failed to load old CA: %v", err)
		}

		cliCtx.FatalIfErrorf(newCA.SaveBundleWith([]*KeyPair{oldCA}, CABundlePath))
		cliCtx.FatalIfErrorf(newCA.SaveCertificate(CACertPath))
		cliCtx.FatalIfErrorf(newCA.SavePrivateKey(CAKeyPath))
	case ActionRotateServer:
		ca, err := loadCertificateAuthority(CACertPath, CAKeyPath)
		if err != nil {
			cliCtx.Fatalf("Failed to load CA: %v", err)
		}
		server := mustMakeServerCertificate(ca)
		cliCtx.FatalIfErrorf(server.SaveCertificate(ServerCertPath))
		cliCtx.FatalIfErrorf(server.SavePrivateKey(ServerKeyPath))
	case ActionRotateClient:
		ca, err := loadCertificateAuthority(CACertPath, CAKeyPath)
		if err != nil {
			cliCtx.Fatalf("Failed to load CA: %v", err)
		}
		client := mustMakeClientCertificate(ca)
		cliCtx.FatalIfErrorf(client.SaveCertificate(ClientCertPath))
		cliCtx.FatalIfErrorf(client.SavePrivateKey(ClientKeyPath))
	default:
		cliCtx.Fatalf("Unknown action: %s", cli.Action)
	}
}
