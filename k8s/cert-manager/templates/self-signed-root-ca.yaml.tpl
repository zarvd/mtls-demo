apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: self-signed-root-ca-0001-issuer
  namespace: cert-manager
spec:
  selfSigned: {}
---
apiVersion: policy.cert-manager.io/v1alpha1
kind: CertificateRequestPolicy
metadata:
  name: allow-self-signed-root-ca-0001-cert
spec:
  selector:
    issuerRef:
      name: self-signed-root-ca-0001-issuer
      kind: Issuer
  allowed:
    isCA: true
    commonName:
      required: true
      value: "self-signed-root-ca-0001"
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cert-manager-policy:self-signed-root-ca-0001-issuer
rules:
  - apiGroups: ["policy.cert-manager.io"]
    resources: ["certificaterequestpolicies"]
    verbs: ["use"]
    resourceNames: ["allow-self-signed-root-ca-0001-cert"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cert-manager-policy:self-signed-root-ca-0001-issuer
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cert-manager-policy:self-signed-root-ca-0001-issuer
subjects:
  - kind: Group
    name: system:authenticated
    apiGroup: rbac.authorization.k8s.io
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: self-signed-root-ca-0001
  namespace: cert-manager
spec:
  isCA: true
  duration: 1h
  renewBefore: 50m
  commonName: self-signed-root-ca-0001
  secretName: self-signed-root-ca-0001
  privateKey:
    rotationPolicy: Always
    algorithm: RSA
    encoding: PKCS1
    size: 4096
  issuerRef:
    name: self-signed-root-ca-0001-issuer
    kind: Issuer
    group: cert-manager.io
