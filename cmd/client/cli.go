package main

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/zarvd/mtls-demo/internal/keypair"
)

const Timeout = 10 * time.Second

type CLI struct {
	ServerAddress string          `required:"" help:"Server address"`
	ServerName    string          `required:"" help:"Server name"`
	KeyPair       keypair.Options `embed:""`
	Interval      time.Duration   `default:"1s" help:"Interval to send requests"`
}

func (c *CLI) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	bundle, err := keypair.NewBundle(c.KeyPair)
	if err != nil {
		return err
	}
	go func() {
		bundle.StartReloadLoop(ctx)
	}()

	tlsConfig := &tls.Config{
		RootCAs:            bundle.CAPool(),
		ServerName:         c.ServerName,
		Certificates:       bundle.KeyPairs(),
		GetConfigForClient: bundle.CreateGetConfigForClient(),
	}

	client := http.Client{
		Timeout: Timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	slog.Info("Sending request to server", slog.String("server", c.ServerAddress))
	resp, err := client.Get(c.ServerAddress)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	slog.Info("Response from server", slog.String("status", resp.Status))
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	slog.Info("Response body", slog.String("body", string(body)))
	return nil
}
