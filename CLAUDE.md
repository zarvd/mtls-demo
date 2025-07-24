# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a comprehensive mTLS (mutual TLS) demonstration project built in Go that showcases cert-manager-based PKI and certificate management in Kubernetes environments. The project consists of three main components:

1. **Server** (`cmd/server/`): HTTPS server that requires client certificate authentication
2. **Client** (`cmd/client/`): HTTP client that continuously makes requests to the server using mTLS
3. **Issuer** (`cmd/issuer/`): Certificate authority and certificate management utility

All components support hot-reloading of certificates through file system watchers, enabling zero-downtime certificate rotation.

## Development Commands

### Build Commands
- `make server` - Build the server binary to `bin/server`
- `make client` - Build the client binary to `bin/client`  
- `make issuer` - Build the certificate issuer binary to `bin/issuer`

### Certificate Management
- `make new-certs` - Generate new CA and all certificates (creates `certs/` directory structure)
- `make rotate-ca` - Rotate the Certificate Authority (creates CA bundle with old CA for compatibility)
- `make rotate-server` - Generate new server certificate
- `make rotate-client` - Generate new client certificate

### Local Development
- `make run-server` - Start the HTTPS server on port 8443 with mTLS enabled
- `make run-client` - Start the client that makes requests to `https://localhost:8443/ping`

### Docker Images
- `make image-server` - Build server Docker image (`ghcr.io/zarvd/mtls-demo/server:v0.0.1`)
- `make image-client` - Build client Docker image (`ghcr.io/zarvd/mtls-demo/client:v0.0.1`)

### Kubernetes Deployment
Navigate to `k8s/` directory for Kubernetes-specific commands:
- `make helm-charts` - Add required Helm repositories (jetstack)
- `make install-cert-manager` - Install cert-manager with CRDs and disabled auto-approval
- `make install-approver-policy` - Install cert-manager approver policy
- `make install-trust-manager` - Install trust-manager for CA bundle distribution
- `make apply` - Deploy all Kubernetes resources (cert-manager config, server, client)
- `make clean` - Remove deployed resources

## Architecture

### Certificate Management (`internal/keypair/`)
- **Bundle** (`bundle.go`): Manages certificate bundles with hot-reloading via fsnotify
- **KeyPair** (`keypair.go`): Core TLS certificate and CA pool management
- **Options** (`options.go`): Configuration structure for certificate paths

### Application Structure
- **Server** (`cmd/server/`):
  - `main.go`: Entry point with signal handling
  - `cli.go`: CLI configuration and startup logic with errgroup for concurrent operations
  - `http.go`: HTTPS server implementation with mTLS requirement
  
- **Client** (`cmd/client/`):
  - `main.go`: Entry point with signal handling  
  - `cli.go`: HTTP client that sends periodic requests with mTLS authentication

- **Issuer** (`cmd/issuer/`):
  - `main.go`: Certificate authority operations (new, rotate-ca, rotate-server, rotate-client)
  - `issue.go`: Certificate generation logic
  - `keypair.go`: KeyPair loading and creation utilities

### Key Features
- **Hot Certificate Reloading**: All components watch certificate files and reload automatically
- **mTLS Authentication**: Server requires valid client certificates signed by the CA
- **CA Rotation Support**: Supports zero-downtime CA rotation using certificate bundles
- **Kubernetes Integration**: Full cert-manager integration with approver policies and trust-manager

### File Paths
- Certificates: `certs/ca.crt`, `certs/ca.key`, `certs/ca-bundle.crt`
- Server certs: `certs/server/tls.crt`, `certs/server/tls.key`  
- Client certs: `certs/client/tls.crt`, `certs/client/tls.key`

### Dependencies
- `github.com/alecthomas/kong` - CLI argument parsing
- `golang.org/x/sync/errgroup` - Concurrent goroutine management
- `github.com/fsnotify/fsnotify` - File system change notifications

## Testing

The project includes end-to-end testing through the client-server interaction. Run both components locally to verify functionality:

1. Generate certificates: `make new-certs`
2. Start server: `make run-server` 
3. Start client: `make run-client`

The client will continuously make requests and log responses, demonstrating successful mTLS communication.