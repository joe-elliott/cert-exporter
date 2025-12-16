package testutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// CertConfig holds configuration for generating a test certificate
type CertConfig struct {
	CommonName   string
	Organization string
	Country      string
	Province     string
	Days         int
	IsCA         bool
}

// CertBundle holds a generated certificate and its key
type CertBundle struct {
	Cert       *x509.Certificate
	CertPEM    []byte
	PrivateKey *rsa.PrivateKey
	PrivateKeyPEM []byte
}

// GenerateCertificate creates a self-signed certificate for testing
func GenerateCertificate(t *testing.T, config CertConfig) *CertBundle {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(config.Days) * 24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   config.CommonName,
			Organization: []string{config.Organization},
			Country:      []string{config.Country},
			Province:     []string{config.Province},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	if config.IsCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	return &CertBundle{
		Cert:          cert,
		CertPEM:       certPEM,
		PrivateKey:    privateKey,
		PrivateKeyPEM: privateKeyPEM,
	}
}

// GenerateSignedCertificate creates a certificate signed by a CA for testing
func GenerateSignedCertificate(t *testing.T, config CertConfig, ca *CertBundle) *CertBundle {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(config.Days) * 24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   config.CommonName,
			Organization: []string{config.Organization},
			Country:      []string{config.Country},
			Province:     []string{config.Province},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, ca.Cert, &privateKey.PublicKey, ca.PrivateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	return &CertBundle{
		Cert:          cert,
		CertPEM:       certPEM,
		PrivateKey:    privateKey,
		PrivateKeyPEM: privateKeyPEM,
	}
}

// CreateCertBundle creates a certificate bundle (cert chain) as PEM
func CreateCertBundle(certs ...*CertBundle) []byte {
	var bundle []byte
	for _, cert := range certs {
		bundle = append(bundle, cert.CertPEM...)
	}
	return bundle
}

// CreatePKCS12Bundle creates a PKCS12 bundle from certificates
func CreatePKCS12Bundle(t *testing.T, cert *CertBundle, caCerts []*CertBundle, password string) []byte {
	t.Helper()

	var cas []*x509.Certificate
	for _, ca := range caCerts {
		cas = append(cas, ca.Cert)
	}

	pfxData, err := pkcs12.Modern.Encode(cert.PrivateKey, cert.Cert, cas, password)
	if err != nil {
		t.Fatalf("Failed to create PKCS12 bundle: %v", err)
	}

	return pfxData
}

// WriteCertToFile writes a certificate to a file
func WriteCertToFile(t *testing.T, certPEM []byte, filename string) {
	t.Helper()

	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}

	if err := os.WriteFile(filename, certPEM, 0644); err != nil {
		t.Fatalf("Failed to write certificate to file: %v", err)
	}
}

// WriteKeyToFile writes a private key to a file
func WriteKeyToFile(t *testing.T, keyPEM []byte, filename string) {
	t.Helper()

	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}

	if err := os.WriteFile(filename, keyPEM, 0600); err != nil {
		t.Fatalf("Failed to write key to file: %v", err)
	}
}

// CreateTempCertDir creates a temporary directory for certificates
func CreateTempCertDir(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	return dir
}
