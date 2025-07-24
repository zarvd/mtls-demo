# Running Locally

This guide walks you through running the mTLS demo components locally for development and testing.

## Prerequisites

Ensure you have Go installed and the project dependencies available.

## Generate CA and TLS Certificates

Generate all required certificates and keys in the `./certs` directory:
- **CA certificates**: `ca.crt` and `ca.key` for the root Certificate Authority
- **CA bundle**: `ca-bundle.crt` for public distribution
- **Server certificates**: Key pairs in `./certs/server/` for HTTPS server authentication  
- **Client certificates**: Key pairs in `./certs/client/` for client authentication

```bash
make new-certs
```

## Run Server (Terminal 1)

Start the HTTPS server with mTLS authentication:

```bash
make run-server
```

The server will:
- Listen on port 8443
- Require client certificate authentication
- Hot-reload certificates when files change
- Log all incoming requests

## Run Client (Terminal 2)

Start the client to make continuous requests to the server:

```bash
make run-client
```

The client will:
- Connect to `https://localhost:8443/ping` 
- Use mTLS authentication with client certificates
- Hot-reload certificates when files change
- Log response details from each request

## Certificate Rotation

The server and client automatically watch certificate files and will reload them when changes are detected, enabling zero-downtime certificate rotation.

### Rotate CA

To rotate the Certificate Authority:

```bash
make rotate-ca
```

This creates a new CA while maintaining a CA bundle that includes the old CA for compatibility during the transition period.

### Rotate Server and Client Certificates

To rotate individual certificates:

```bash
make rotate-server
make rotate-client
```

Both server and client will automatically detect and reload the new certificates without requiring a restart.
