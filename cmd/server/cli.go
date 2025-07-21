package main

import (
	"context"

	"golang.org/x/sync/errgroup"

	"github.com/zarvd/mtls-demo/internal/keypair"
)

type CLI struct {
	KeyPair keypair.Options `embed:""`
	Port    int             `required:"" help:"Port to listen on"`
}

func (c *CLI) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	bundle, err := keypair.NewBundle(c.KeyPair)
	if err != nil {
		return err
	}

	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		bundle.StartReloadLoop(ctx)
		return nil
	})

	eg.Go(func() error {
		return RunHTTPServer(ctx, c.Port, bundle)
	})
	return eg.Wait()
}
