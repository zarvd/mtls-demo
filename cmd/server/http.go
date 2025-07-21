package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/zarvd/mtls-demo/internal/keypair"
)

func RunHTTPServer(ctx context.Context, port int, bundle *keypair.Bundle) error {
	addr := fmt.Sprintf(":%d", port)

	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		t1 := time.Now()
		slog.Info("Incoming request", slog.String("method", r.Method), slog.String("url", r.URL.String()))
		defer slog.Info("Request handled", slog.Duration("duration", time.Since(t1)))

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello, World!"))
	})

	tlsConfig := &tls.Config{
		ClientCAs:          bundle.CAPool(),
		ClientAuth:         tls.RequireAndVerifyClientCert,
		GetConfigForClient: bundle.CreateGetConfigForClient(),
	}

	server := http.Server{
		Addr:      addr,
		TLSConfig: tlsConfig,
		Handler:   mux,
	}
	slog.Info("Starting server", slog.String("addr", addr))
	defer slog.Info("Server stopped")

	go func() {
		if err := server.ListenAndServeTLS("", ""); err != nil {
			slog.Error("Failed to start server", slog.String("error", err.Error()))
		}
	}()

	<-ctx.Done()
	return server.Shutdown(ctx)
}
