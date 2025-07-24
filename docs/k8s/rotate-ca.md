# CA Certificate Rotation

Certificate Authority (CA) rotation is a critical security practice that ensures continuous service availability during certificate lifecycle management. This guide outlines a zero-downtime approach using a two-phase rotation strategy.

## Rotation Strategy

The two-phase approach ensures zero-downtime certificate rotation:

**Phase 1: CA Bundle Propagation**
- Distribute the new CA certificate to all components
- Maintain trust for both old and new CA certificates
- Continue issuing certificates from the old CA

**Phase 2: Certificate Issuer Migration**  
- Switch the certificate issuer to use the new CA
- Generate fresh certificates signed by the new CA
- Old certificates remain valid until natural expiration

## Step 1: Generate New CA Certificate

Create a new self-signed root CA certificate:

```bash
cd ./k8s
./cert-manager/generate-self-signed-root-ca.sh
```

This generates a new CA certificate file (e.g., `self-signed-root-ca-0002.yaml`). Apply it to the cluster:

```bash
kubectl apply -f ./cert-manager/self-signed-root-ca-0002.yaml
```

## Step 2: Update CA Bundle Distribution

Update the trust-manager Bundle to include both old and new CA certificates by editing `./k8s/cert-manager/ca-bundle.yaml`:

```diff
apiVersion: trust.cert-manager.io/v1alpha1
kind: Bundle
metadata:
  name: intra-cluster-mtls-ca-bundle
spec:
  sources:
    - secret:
        name: self-signed-root-ca-0001
        key: tls.crt
+   - secret:
+       name: self-signed-root-ca-0002
+       key: tls.crt
  target:
    namespaceSelector:
      matchLabels:
        mtls.zarvd.dev/intra-cluster-mtls: "true"
    configMap:
      key: ca-bundle.pem
      metadata:
        labels:
          app.kubernetes.io/component: "trust-bundle"
```

Apply the updated bundle configuration:

```bash
kubectl apply -f ./k8s/cert-manager/ca-bundle.yaml
```

## Step 3: Switch Certificate Issuer

Update the cert-manager ClusterIssuer to use the new CA for certificate generation by editing `./k8s/cert-manager/ca-clusterissuer.yaml`:

```diff
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: ca-issuer
spec:
  ca:
-   secretName: self-signed-root-ca-0001
+   secretName: self-signed-root-ca-0002
```

Apply the issuer configuration:

```bash
kubectl apply -f ./k8s/cert-manager/ca-clusterissuer.yaml
```

## Step 4: Force Certificate Renewal (Optional)

To immediately renew all certificates with the new CA, use the cert-manager CLI:

```bash
cmctl renew --all --namespace=mtls-server
cmctl renew --all --namespace=mtls-client
```

**Note:** This step is optional as certificates will naturally renew using the new CA when they approach expiration.

## Verification

Verify the rotation was successful:

```bash
# Check certificate status
kubectl get certificates -A

# Verify CA bundle distribution
kubectl get configmaps -A -l app.kubernetes.io/component=trust-bundle

# Check application logs for successful mTLS handshakes
kubectl logs -f deployment/mtls-server -n mtls-server
kubectl logs -f deployment/mtls-client -n mtls-client
```

