package mtls

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"sync"
	"time"
)

func PanicIfErr(err error) {
	if err != nil {
		panic(err)
	}
}

func ToCertificatePEM(certBytes []byte) []byte {
	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	return certPEM.Bytes()
}

func ToPrivateKeyPEM(privateKey crypto.PrivateKey) []byte {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	PanicIfErr(err)
	keyPEM := new(bytes.Buffer)
	pem.Encode(keyPEM, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})
	return keyPEM.Bytes()
}

type CA struct {
	Certificate *x509.Certificate
	PrivateKey  crypto.PrivateKey
}

func (ca *CA) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.Certificate)
	return pool
}

func (ca *CA) Sign(template *x509.Certificate) *TLSKeyPair {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	PanicIfErr(err)
	certBytes, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, &privateKey.PublicKey, ca.PrivateKey)
	PanicIfErr(err)
	certPEM, pkPEM := ToCertificatePEM(certBytes), ToPrivateKeyPEM(privateKey)
	cert, err := tls.X509KeyPair(certPEM, pkPEM)
	PanicIfErr(err)
	return &TLSKeyPair{
		Certificate: &cert,
		CAs:         ca.pool(),
		Raw:         NewTLSKeyPairRaw(ToCertificatePEM(ca.Certificate.Raw), certPEM, pkPEM),
	}
}

func fakeCA(template *x509.Certificate) *CA {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	PanicIfErr(err)
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	PanicIfErr(err)
	cert, err := x509.ParseCertificate(certBytes)
	PanicIfErr(err)
	ca := &CA{
		Certificate: cert,
		PrivateKey:  privateKey,
	}
	return ca
}

func fakeCATemplate(mutates ...func(template *x509.Certificate)) *x509.Certificate {
	now := time.Now()
	subject := pkix.Name{
		CommonName: "test-ca",
	}
	template := &x509.Certificate{
		Subject:               subject,
		SerialNumber:          big.NewInt(now.Unix()),
		NotBefore:             now,
		NotAfter:              now.Add(1 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		BasicConstraintsValid: true,
	}

	for _, mutate := range mutates {
		mutate(template)
	}

	return template
}

func fakeServerTemplate(mutates ...func(template *x509.Certificate)) *x509.Certificate {
	now := time.Now()
	subject := pkix.Name{
		CommonName: "test-server",
	}
	template := &x509.Certificate{
		Subject:   subject,
		NotBefore: now,
		NotAfter:  now.Add(30 * time.Minute),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}

	for _, mutate := range mutates {
		mutate(template)
	}
	return template
}

func fakeClientTemplate(mutates ...func(template *x509.Certificate)) *x509.Certificate {
	now := time.Now()
	subject := pkix.Name{
		CommonName: "test-client",
	}
	template := &x509.Certificate{
		Subject:   subject,
		NotBefore: now,
		NotAfter:  now.Add(30 * time.Minute),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
	}

	for _, mutate := range mutates {
		mutate(template)
	}

	return template
}

type fakeKeyPairLoader struct {
	mu      sync.Mutex
	keyPair *TLSKeyPair
}

func (l *fakeKeyPairLoader) SetKeyPair(keyPair *TLSKeyPair) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.keyPair = keyPair
}

func (l *fakeKeyPairLoader) KeyPair() *TLSKeyPair {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.keyPair
}

type KeyPairFiles struct {
	CA          *os.File
	Certificate *os.File
	Key         *os.File
}

func MustTempKeyPairFiles() *KeyPairFiles {
	const DirPattern = "securetransport-tls-test"
	dir, err := os.MkdirTemp(os.TempDir(), DirPattern)
	PanicIfErr(err)
	ca, err := os.CreateTemp(dir, "ca.pem")
	PanicIfErr(err)
	certificate, err := os.CreateTemp(dir, "cert.pem")
	PanicIfErr(err)
	key, err := os.CreateTemp(dir, "key.pem")
	PanicIfErr(err)
	return &KeyPairFiles{
		CA:          ca,
		Certificate: certificate,
		Key:         key,
	}
}

func (fs *KeyPairFiles) Save(ca *CA, keyPair *TLSKeyPair) {
	fs.SaveCA(ca)
	fs.SaveCertificate(keyPair.Certificate)
	fs.SaveKey(keyPair.Certificate.PrivateKey)
}

func (fs *KeyPairFiles) SaveCA(ca *CA) {
	pem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.Certificate.Raw,
	})

	_, err := fs.CA.WriteAt(pem, 0) // overwrite file
	PanicIfErr(err)
}

func (fs *KeyPairFiles) SaveCertificate(cert *tls.Certificate) {
	pem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Leaf.Raw,
	})

	_, err := fs.Certificate.WriteAt(pem, 0) // overwrite file
	PanicIfErr(err)
}

func (fs *KeyPairFiles) SaveKey(key crypto.PrivateKey) {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	PanicIfErr(err)
	pem := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})

	_, err = fs.Key.WriteAt(pem, 0) // overwrite file
	PanicIfErr(err)
}

func (fs *KeyPairFiles) Close() error {
	return errors.Join(
		fs.CA.Close(),
		fs.Certificate.Close(),
		fs.Key.Close(),
		os.Remove(fs.CA.Name()),
		os.Remove(fs.Certificate.Name()),
		os.Remove(fs.Key.Name()),
	)
}
