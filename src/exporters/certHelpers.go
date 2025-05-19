package exporters

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/pavlo-v-chernykh/keystore-go/v4"
	"software.sslmate.com/src/go-pkcs12"
)

type certMetric struct {
	durationUntilExpiry float64
	notAfter, notBefore float64
	issuer              string
	cn                  string
	Alias               string // New field for JKS alias
}

func secondsToExpiryFromCertAsFile(file string, password string) ([]certMetric, error) {
	certBytes, err := os.ReadFile(file)
	if err != nil {
		return []certMetric{}, err
	}

	return secondsToExpiryFromCertAsBytes(certBytes, password)
}

func secondsToExpiryFromCertAsBase64String(s string, password string) ([]certMetric, error) {
	certBytes, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return []certMetric{}, err
	}
	return secondsToExpiryFromCertAsBytes(certBytes, password)
}

func secondsToExpiryFromCertAsBytes(certBytes []byte, certPassword string) ([]certMetric, error) {
	var pemMetrics, pkcsMetrics, jksMetrics []certMetric
	var errPem, errPkcs, errJks error
	var parsedPem, parsedPkcs, parsedJks bool

	// Try PEM
	parsedPem, pemMetrics, errPem = parseAsPEM(certBytes)
	if parsedPem {
		// If parsedPem is true, it means the data was recognized as PEM.
		// errPem might be non-nil if there was an issue with intermediate certs.
		return pemMetrics, errPem
	}
	// errPem contains the reason it wasn't parsed as PEM (e.g., "Failed to parse as a pem")

	// Try PKCS12
	parsedPkcs, pkcsMetrics, errPkcs = parseAsPKCS(certBytes, certPassword)
	if parsedPkcs {
		// If parsedPkcs is true, it means pkcs12.DecodeChain succeeded.
		// errPkcs should be nil in this case according to its implementation.
		return pkcsMetrics, errPkcs
	}
	// errPkcs contains the reason it wasn't parsed as PKCS12

	// Try JKS
	parsedJks, jksMetrics, errJks = parseAsJKS(certBytes, certPassword)
	if parsedJks {
		// If parsedJks is true, it means ks.Load succeeded.
		// errJks might be non-nil if there was an issue processing an entry or cert within the JKS.
		return jksMetrics, errJks
	}
	// errJks contains the reason it wasn't parsed as JKS

	// If all attempts fail
	return nil, fmt.Errorf("failed to parse certificate data: as pem (error: %v), as pkcs12 (error: %v), as jks (error: %v)", errPem, errPkcs, errJks)
}

func getCertificateMetrics(cert *x509.Certificate) certMetric {
	var metric certMetric
	metric.notAfter = float64(cert.NotAfter.Unix())
	metric.notBefore = float64(cert.NotBefore.Unix())
	metric.durationUntilExpiry = time.Until(cert.NotAfter).Seconds()
	metric.issuer = cert.Issuer.CommonName
	metric.cn = cert.Subject.CommonName
	return metric
}

func parseAsPKCS(certBytes []byte, certPassword string) (bool, []certMetric, error) {
	var metrics []certMetric
	_, cert, caCerts, err := pkcs12.DecodeChain(certBytes, certPassword)
	if err != nil {
		return false, nil, err
	}
	metric := getCertificateMetrics(cert)
	metrics = append(metrics, metric)
	for _, cert := range caCerts {
		metric := getCertificateMetrics(cert)
		metrics = append(metrics, metric)
	}
	return true, metrics, nil
}

func parseAsJKS(certBytes []byte, certPassword string) (bool, []certMetric, error) {
	var metrics []certMetric

	ks := keystore.New()
	// keystore.Load takes an io.Reader and a password []byte
	err := ks.Load(bytes.NewReader(certBytes), []byte(certPassword))
	if err != nil {
		// This indicates it's not a JKS file, the password is wrong, or it's corrupted.
		return false, nil, fmt.Errorf("failed to decode JKS: %w", err)
	}

	// If ks.Load succeeded, we consider it "parsed" as JKS format.
	// Subsequent errors are issues within a valid JKS structure.

	aliases := ks.Aliases()
	if len(aliases) == 0 {
		// Empty but valid JKS.
		return true, metrics, nil // metrics will be empty
	}

	for _, alias := range aliases {
		// Only process TrustedCertificateEntry types
		if ks.IsTrustedCertificateEntry(alias) {
			tcEntry, entryErr := ks.GetTrustedCertificateEntry(alias)
			if entryErr != nil {
				// If a TrustedCertificateEntry is found but cannot be read, return an error.
				return true, metrics, fmt.Errorf("failed to get trusted certificate entry '%s' from JKS: %w", alias, entryErr)
			}
			cert, parseErr := x509.ParseCertificate(tcEntry.Certificate.Content)
			if parseErr != nil {
				// If a TrustedCertificateEntry is read but the cert cannot be parsed, return an error.
				return true, metrics, fmt.Errorf("failed to parse trusted certificate for alias '%s': %w", alias, parseErr)
			}
			m := getCertificateMetrics(cert)
			m.Alias = alias // Set the JKS alias
			metrics = append(metrics, m)
		} else if ks.IsPrivateKeyEntry(alias) {
			// Attempt to get the PrivateKeyEntry. The certPassword is the keystore password.
			// This will work if the private key is not password-protected or shares the keystore password.
			// If the private key has its own distinct password, this call will likely fail.
			pkEntry, entryErr := ks.GetPrivateKeyEntry(alias, []byte(certPassword))
			if entryErr != nil {
				// Error retrieving PrivateKeyEntry, possibly due to incorrect key-specific password.
				return true, metrics, fmt.Errorf("failed to get private key entry '%s' (key may have a different password than the keystore): %w", alias, entryErr)
			}

			for i, certInChain := range pkEntry.CertificateChain {
				cert, parseErr := x509.ParseCertificate(certInChain.Content)
				if parseErr != nil {
					return true, metrics, fmt.Errorf("failed to parse certificate in chain for private key entry '%s' at index %d: %w", alias, i, parseErr)
				}
				m := getCertificateMetrics(cert)
				m.Alias = alias // Set the JKS alias
				metrics = append(metrics, m)
			}
		}
	}
	return true, metrics, nil
}

func parseAsPEM(certBytes []byte) (bool, []certMetric, error) {
	var metrics []certMetric
	var blocks []*pem.Block

	block, rest := pem.Decode(certBytes)
	if block == nil {
		return false, metrics, fmt.Errorf("Failed to parse as a pem")
	}
	// Remove trailing whitespaces to prevent possible error in loop
	rest = []byte(strings.TrimRightFunc(string(rest), unicode.IsSpace))
	blocks = append(blocks, block)
	// Export the remaining certificates in the certificate chain
	for len(rest) != 0 {
		block, rest = pem.Decode(rest)
		if block == nil {
			return true, metrics, fmt.Errorf("Failed to parse intermediate as a pem")
		}
		if block.Type == "CERTIFICATE" {
			blocks = append(blocks, block)
		}
	}
	for _, block := range blocks {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return true, metrics, err
		}
		metric := getCertificateMetrics(cert)
		metrics = append(metrics, metric)
	}
	return true, metrics, nil
}
