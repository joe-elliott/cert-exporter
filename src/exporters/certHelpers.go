package exporters

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/golang/glog"
	"github.com/joe-elliott/cert-exporter/src/args"
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

func matchGlobs(s string, globs args.GlobArgs) bool {
	if s == "" { // An empty string (e.g. alias for non-JKS or empty CN) should not match unless glob is explicitly "" or "*"
		for _, pattern := range globs {
			if pattern == "" || pattern == "*" { // only match if glob is "" or "*"
				return true
			}
		}
		return false
	}
	for _, pattern := range globs {
		matched, err := filepath.Match(pattern, s)
		if err != nil {
			glog.Warningf("Malformed glob pattern '%s' while matching string '%s': %v", pattern, s, err)
			continue // Treat malformed pattern as non-matching for this specific pattern
		}
		if matched {
			return true
		}
	}
	return false
}

func filterMetrics(metrics []certMetric, excludeCNGlobs args.GlobArgs, excludeAliasGlobs args.GlobArgs, excludeIssuerGlobs args.GlobArgs) []certMetric {
	if len(excludeCNGlobs) == 0 && len(excludeAliasGlobs) == 0 && len(excludeIssuerGlobs) == 0 {
		return metrics
	}

	var filtered []certMetric
	for _, m := range metrics {
		excluded := false
		if len(excludeCNGlobs) > 0 && matchGlobs(m.cn, excludeCNGlobs) {
			excluded = true
		}
		if !excluded && len(excludeAliasGlobs) > 0 && m.Alias != "" && matchGlobs(m.Alias, excludeAliasGlobs) {
			excluded = true
		}
		if !excluded && len(excludeIssuerGlobs) > 0 && matchGlobs(m.issuer, excludeIssuerGlobs) {
			excluded = true
		}

		if !excluded {
			filtered = append(filtered, m)
		}
	}
	return filtered
}

func secondsToExpiryFromCertAsFile(file string, password string, excludeCNGlobs args.GlobArgs, excludeAliasGlobs args.GlobArgs, excludeIssuerGlobs args.GlobArgs) ([]certMetric, error) {
	certBytes, err := os.ReadFile(file)
	if err != nil {
		return []certMetric{}, err
	}
	return secondsToExpiryFromCertAsBytes(certBytes, password, excludeCNGlobs, excludeAliasGlobs, excludeIssuerGlobs)
}

func secondsToExpiryFromCertAsBase64String(s string, password string, excludeCNGlobs args.GlobArgs, excludeAliasGlobs args.GlobArgs, excludeIssuerGlobs args.GlobArgs) ([]certMetric, error) {
	certBytes, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return []certMetric{}, err
	}
	return secondsToExpiryFromCertAsBytes(certBytes, password, excludeCNGlobs, excludeAliasGlobs, excludeIssuerGlobs)
}

func secondsToExpiryFromCertAsBytes(certBytes []byte, certPassword string, excludeCNGlobs args.GlobArgs, excludeAliasGlobs args.GlobArgs, excludeIssuerGlobs args.GlobArgs) ([]certMetric, error) {
	var pemMetrics, pkcsMetrics, jksMetrics []certMetric
	var errPem, errPkcs, errJks error
	var parsedPem, parsedPkcs, parsedJks bool

	// Try PEM
	parsedPem, pemMetrics, errPem = parseAsPEM(certBytes)
	if parsedPem {
		// If parsedPem is true, it means the data was recognized as PEM.
		// errPem might be non-nil if there was an issue with intermediate certs.
		return filterMetrics(pemMetrics, excludeCNGlobs, excludeAliasGlobs, excludeIssuerGlobs), errPem
	}
	// errPem contains the reason it wasn't parsed as PEM (e.g., "Failed to parse as a pem")

	// Try PKCS12
	parsedPkcs, pkcsMetrics, errPkcs = parseAsPKCS(certBytes, certPassword)
	if parsedPkcs {
		// If parsedPkcs is true, it means pkcs12.DecodeChain succeeded.
		// errPkcs should be nil in this case according to its implementation.
		return filterMetrics(pkcsMetrics, excludeCNGlobs, excludeAliasGlobs, excludeIssuerGlobs), errPkcs
	}
	// errPkcs contains the reason it wasn't parsed as PKCS12

	// Try JKS
	parsedJks, jksMetrics, errJks = parseAsJKS(certBytes, certPassword)
	if parsedJks {
		// If parsedJks is true, it means ks.Load succeeded.
		// errJks might be non-nil if there was an issue processing an entry or cert within the JKS.
		return filterMetrics(jksMetrics, excludeCNGlobs, excludeAliasGlobs, excludeIssuerGlobs), errJks
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
	var pemBlockDecoded bool // Tracks if at least one PEM block was successfully decoded

	data := certBytes
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			// No more PEM blocks can be decoded from the remaining data.
			// If 'rest' is not empty here, it means there was trailing non-PEM data,
			// which is acceptable if we've already found PEM blocks.
			break
		}
		pemBlockDecoded = true // Mark that we've found at least one PEM block

		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				// Log the error for this specific certificate but continue processing others.
				glog.Warningf("Error parsing an X.509 certificate from a PEM block: %v", err)
			} else {
				metric := getCertificateMetrics(cert)
				metrics = append(metrics, metric)
			}
		} else {
			// A PEM block was found, but it's not of type "CERTIFICATE".
			// Log this information if verbose logging is enabled and skip it.
			glog.V(2).Infof("Skipping PEM block of type '%s'", block.Type)
		}

		// Move to the rest of the data for the next iteration.
		data = rest
	}

	if !pemBlockDecoded {
		// If no PEM blocks were decoded at all, the input is not considered PEM.
		return false, nil, fmt.Errorf("no PEM data found in input")
	}

	// If at least one PEM block was decoded, the input is considered to be PEM.
	// 'metrics' will contain all successfully parsed certificates.
	return true, metrics, nil
}
