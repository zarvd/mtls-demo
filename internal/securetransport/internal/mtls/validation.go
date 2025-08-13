package mtls

import (
	"crypto/x509"
	"fmt"
	"slices"
	"time"
)

const MinimumCertificateValidityDuration = 10 * time.Minute

func validateKeyPair(keyPair *TLSKeyPair) error {
	if keyPair.Certificate == nil {
		return fmt.Errorf("certificate is nil")
	}
	if keyPair.CAs == nil {
		return fmt.Errorf("CA pool is nil")
	}
	now := time.Now()
	if keyPair.Certificate.Leaf.NotBefore.After(now) {
		return fmt.Errorf("certificate is not valid yet: %s", keyPair.Certificate.Leaf.NotBefore)
	}
	if keyPair.Certificate.Leaf.NotAfter.Before(now.Add(MinimumCertificateValidityDuration)) {
		return fmt.Errorf("certificate will expire in less than %s", MinimumCertificateValidityDuration)
	}

	return nil
}

func ValidateKeyPairForServerUsage(keyPair *TLSKeyPair) error {
	if err := validateKeyPair(keyPair); err != nil {
		return err
	}
	if !slices.Contains(keyPair.Certificate.Leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		return fmt.Errorf("certificate is not valid for server usage")
	}
	verifyOptions := x509.VerifyOptions{
		Roots: keyPair.CAs,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}
	if _, err := keyPair.Certificate.Leaf.Verify(verifyOptions); err != nil {
		return fmt.Errorf("verify certificate signature: %w", err)
	}
	return nil
}

func ValidateKeyPairForClientUsage(keyPair *TLSKeyPair) error {
	if err := validateKeyPair(keyPair); err != nil {
		return err
	}
	if !slices.Contains(keyPair.Certificate.Leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		return fmt.Errorf("certificate is not valid for client usage")
	}
	verifyOptions := x509.VerifyOptions{
		Roots: keyPair.CAs,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
	}
	if _, err := keyPair.Certificate.Leaf.Verify(verifyOptions); err != nil {
		return fmt.Errorf("verify certificate signature: %w", err)
	}
	return nil
}
