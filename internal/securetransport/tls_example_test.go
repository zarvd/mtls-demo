package securetransport

import (
	"context"
	"net"
	"net/http"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/emptypb"
)

func ExampleNewLocalFileClientTLSConfigLoader_forHTTPClient() {
	loader, err := NewLocalFileClientTLSConfigLoader(LocalFileTLSConfigLoaderOptions{
		CABundle:       "ca.pem",
		Certificate:    "cert.pem",
		Key:            "key.pem",
		ReloadInterval: 10 * time.Second,
	})
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := loader.StartLoop(ctx); err != nil {
			panic(err)
		}
	}()

	client := http.Client{
		Transport: loader.HTTPRoundTripper(),
	}

	client.Get("https://example.com")
}

func ExampleNewLocalFileServerTLSConfigLoader_forHTTPServer() {
	loader, err := NewLocalFileServerTLSConfigLoader(LocalFileTLSConfigLoaderOptions{
		CABundle:       "ca.pem",
		Certificate:    "cert.pem",
		Key:            "key.pem",
		ReloadInterval: 10 * time.Second,
	})
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := loader.StartLoop(ctx); err != nil {
			panic(err)
		}
	}()

	server := http.Server{
		Addr: ":8080",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
		TLSConfig: loader.ServerTLSConfig(),
	}

	if err := server.ListenAndServeTLS("", ""); err != nil {
		panic(err)
	}
}
func ExampleNewLocalFileClientTLSConfigLoader_forGRPCClient() {
	loader, err := NewLocalFileClientTLSConfigLoader(LocalFileTLSConfigLoaderOptions{
		CABundle:       "ca.pem",
		Certificate:    "cert.pem",
		Key:            "key.pem",
		ReloadInterval: 10 * time.Second,
	})
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := loader.StartLoop(ctx); err != nil {
			panic(err)
		}
	}()

	conn, err := grpc.NewClient(
		"https://example.com",
		grpc.WithTransportCredentials(loader.GRPCCredentials()),
	)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	var out *emptypb.Empty
	if err := conn.Invoke(ctx, "ping", &emptypb.Empty{}, out); err != nil {
		panic(err)
	}
}

func ExampleNewLocalFileServerTLSConfigLoader_forGRPCServer() {
	loader, err := NewLocalFileServerTLSConfigLoader(LocalFileTLSConfigLoaderOptions{
		CABundle:       "ca.pem",
		Certificate:    "cert.pem",
		Key:            "key.pem",
		ReloadInterval: 10 * time.Second,
	})
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := loader.StartLoop(ctx); err != nil {
			panic(err)
		}
	}()

	server := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(loader.ServerTLSConfig())),
	)

	lis, err := net.Listen("tcp", ":8080")
	if err != nil {
		panic(err)
	}
	defer lis.Close()

	if err := server.Serve(lis); err != nil {
		panic(err)
	}
}
