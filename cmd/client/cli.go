package main

import (
	"context"
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

	tlsConfig := bundle.CreateTLSConfigForClient()
	tlsConfig.ServerName = c.ServerName

	client := http.Client{
		Timeout: Timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	ticker := time.NewTicker(c.Interval)
	defer ticker.Stop()

	sendRequest := func() error {
		client.CloseIdleConnections()
		t1 := time.Now()
		resp, err := client.Get(c.ServerAddress)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		slog.Info("Response from server",
			slog.String("server", c.ServerAddress),
			slog.String("status", resp.Status),
			slog.Duration("duration", time.Since(t1)),
			slog.String("body", string(body)),
		)
		return nil
	}

	for {
		select {
		case <-ticker.C:
			if err := sendRequest(); err != nil {
				slog.Error("Failed to send request", slog.String("error", err.Error()))
				panic("failed to send request")
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
