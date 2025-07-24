# Deploy

This guide walks through deploying the complete mTLS demo application on Kubernetes.

## Quick Deployment

There is a single make command that provisions everything needed for the mTLS demo:

```bash
cd ./k8s
make apply
```

This command will:
1. Generate and apply a self-signed root CA certificate
2. Configure cert-manager cluster issuer to use the CA
3. Deploy the mTLS server in the `mtls-server` namespace
4. Deploy the mTLS client in the `mtls-client` namespace
5. Set up automatic certificate provisioning for both components

## Verify Deployment

Check that all pods are running successfully:

```bash
kubectl get pods -n mtls-server
kubectl get pods -n mtls-client
```

## View Application Logs

Monitor the client making requests to the server:

```bash
# View client logs (shows HTTP requests)
kubectl logs -f deployment/mtls-client -n mtls-client

# View server logs (shows incoming requests)  
kubectl logs -f deployment/mtls-server -n mtls-server
```

## Architecture

The deployment creates:
- **mtls-server namespace**: Contains the HTTPS server requiring client certificates
- **mtls-client namespace**: Contains the client making periodic requests
- **Certificate resources**: Automatically provisioned server and client certificates
- **ConfigMap CA bundles**: Distributed by trust-manager for certificate validation

## Cleanup

To remove all deployed resources:

```bash
cd ./k8s
make clean
```

