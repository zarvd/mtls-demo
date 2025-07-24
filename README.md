# mTLS DEMO

This is a comprehensive demonstration project that showcases how to use cert-manager to build a robust Public Key Infrastructure (PKI) and manage TLS certificates in Kubernetes environments. The project features two HTTPS servers and a client application implemented in Go, which continuously exchange HTTPS requests within the cluster using mutual TLS (mTLS) authentication for enhanced security.

The demonstration highlights several key aspects of certificate management:

- **Automated Certificate Provisioning**: Using cert-manager to automatically provision and manage X.509 certificates
- **Self-Signed CA Infrastructure**: Building a complete PKI with self-signed Certificate Authorities
- **mTLS Authentication**: Implementing mutual TLS between services for secure communication
- **Certificate Policies**: Enforcing certificate request policies to maintain security standards
- **Zero-Downtime CA Rotation**: Leveraging trust-manager to perform seamless CA certificate rotation without service interruption

This project serves as a practical guide for implementing enterprise-grade certificate management in Kubernetes clusters, demonstrating best practices for secure service-to-service communication in cloud-native environments.

Guides:
- [Run on local](./docs/local.md)
- [Run on k8s with cert-manager](./docs/k8s/README.md)
