package main

import (
	"context"
	"log/slog"
	"os/signal"
	"syscall"

	"github.com/alecthomas/kong"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	cli := new(CLI)
	cliCtx := kong.Parse(cli)
	cliCtx.BindTo(ctx, (*context.Context)(nil))

	slog.Info("Starting server")
	if err := cliCtx.Run(ctx, cli); err != nil {
		slog.Error("Failed to start server", slog.String("error", err.Error()))
	}
	slog.Info("Server stopped")
}
