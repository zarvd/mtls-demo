# Setup

## Prerequisites

Before setting up the mTLS demo on Kubernetes, ensure you have:

- A running Kubernetes cluster (local or cloud-based)
- `kubectl` configured to access your cluster
- `helm` v3.x installed on your local machine
- Cluster admin permissions (required for cert-manager CRDs)

## Install cert-manager Components

The setup process installs the following components in order:

1. **cert-manager** - Core certificate management controller
2. **approver-policy** - Policy-based certificate request approval
3. **trust-manager** - CA bundle distribution across namespaces

Run the installation commands from the project's k8s directory:

```bash
cd ./k8s
make helm-charts          # Add required Helm repositories
make install-cert-manager # Install cert-manager with CRDs
make install-approver-policy
make install-trust-manager
```

## Verification

Verify the installation by checking that all cert-manager pods are running:

```bash
kubectl get pods -n cert-manager
```

You should see pods for cert-manager, cert-manager-webhook, cert-manager-cainjector, and trust-manager in a `Running` state.

