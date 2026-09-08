package exporters

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/bmatcuk/doublestar/v4"
	"software.sslmate.com/src/go-pkcs12"
)

type certMetric struct {
	durationUntilExpiry float64
	notAfter, notBefore float64
	issuer              string
	cn                  string
	// serial is the certificate serial number in lowercase hex. Used as a
	// Prometheus label so multiple PEMs that share cn/issuer (e.g. rotated
	// service-CA bundles) do not overwrite one another.
	serial string
}

func secondsToExpiryFromCertAsFile(file string) ([]certMetric, error) {
	certBytes, err := os.ReadFile(file)
	if err != nil {
		return []certMetric{}, err
	}

	return secondsToExpiryFromCertAsBytes(certBytes, "")
}

func secondsToExpiryFromCertAsBase64String(s string) ([]certMetric, error) {
	certBytes, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return []certMetric{}, err
	}

	return secondsToExpiryFromCertAsBytes(certBytes, "")
}

func secondsToExpiryFromCertAsBytes(certBytes []byte, certPassword string) ([]certMetric, error) {
	var metrics []certMetric

	parsed, metrics, pemErr := parseAsPEM(certBytes)
	if parsed {
		return metrics, pemErr
	}
	// Fall back to PKCS#12 for binary keystore formats (.p12/.pfx).
	parsed, metrics, pkcsErr := parseAsPKCS(certBytes, certPassword)
	if parsed {
		return metrics, nil
	}
	// Prefer the PEM error when the payload is clearly textual; PKCS#12 ASN.1
	// errors on garbage text are noisy and change across crypto/asn1 versions.
	if pemErr != nil && !looksLikePKCS12(certBytes) {
		return nil, fmt.Errorf("failed to parse as pem and pkcs12: %w", pemErr)
	}
	if pkcsErr != nil {
		return nil, fmt.Errorf("failed to parse as pem and pkcs12: %w", pkcsErr)
	}
	return nil, fmt.Errorf("failed to parse as pem and pkcs12")
}

// looksLikePKCS12 reports whether data might be a PKCS#12/PFX binary.
// PKCS#12 is an ASN.1 SEQUENCE (tag 0x30); PEM text never starts that way.
func looksLikePKCS12(data []byte) bool {
	return len(data) > 0 && data[0] == 0x30
}

func getCertificateMetrics(cert *x509.Certificate) certMetric {
	var metric certMetric
	metric.notAfter = float64(cert.NotAfter.Unix())
	metric.notBefore = float64(cert.NotBefore.Unix())
	metric.durationUntilExpiry = time.Until(cert.NotAfter).Seconds()
	metric.issuer = cert.Issuer.CommonName
	metric.cn = cert.Subject.CommonName
	if cert.SerialNumber != nil {
		metric.serial = cert.SerialNumber.Text(16)
	}
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

func parseAsPEM(certBytes []byte) (bool, []certMetric, error) {
	var metrics []certMetric
	var blocks []*pem.Block

	block, rest := pem.Decode(certBytes)
	if block == nil {
		return false, metrics, fmt.Errorf("Failed to parse as a pem")
	}
	// Remove trailing whitespaces to prevent possible error in loop
	rest = []byte(strings.TrimRightFunc(string(rest), unicode.IsSpace))
	if block.Type == "CERTIFICATE" {
		blocks = append(blocks, block)
	}
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

// certGlobSeparator stands in for "/" while glob matching CNs and issuers.
// See flattenGlobPath.
const certGlobSeparator = "\x00"

// flattenGlobPath folds "/" to a sentinel so that it stops acting as a glob
// separator.
//
// Certificate CNs are not paths, so an operator writing "*" means "any CN",
// including URI-style names such as "spiffe://cluster.local/ns/foo". Both
// doublestar and filepath.Match refuse to let "*" cross a separator, so
// pattern and value are folded alike before matching. As a result "*" and
// "**" match anything, and "?" matches "/" as well.
//
// NUL does not occur in an X.509 name in practice, but Go does decode one from
// a UTF8String, so it is remapped first: without that, a "/"-bearing pattern
// would match a CN containing NUL.
func flattenGlobPath(s string) string {
	s = strings.ReplaceAll(s, certGlobSeparator, "\uFFFD")
	return strings.ReplaceAll(s, "/", certGlobSeparator)
}

// ValidateCertGlobs reports an error for the first malformed pattern in globs.
//
// Validity depends only on the pattern, so patterns are checked once at
// startup and matching never has to report a syntax error per certificate.
// Note that "{" and "}" are metacharacters: a literal brace in a CN has to be
// escaped as "\{" or "\}", and an unescaped one is rejected here.
func ValidateCertGlobs(globs []string) error {
	for _, pattern := range globs {
		if !doublestar.ValidatePattern(flattenGlobPath(pattern)) {
			return fmt.Errorf("malformed glob pattern %q; escape glob metacharacters such as [ { } with a backslash", pattern)
		}
	}
	return nil
}

// matchGlobs reports whether s matches any of the given glob patterns.
//
// Patterns are expected to have passed ValidateCertGlobs. A certificate with
// no CN (or no issuer CN) is matched only by a pattern that matches the empty
// string, that is "", "*", "**", or an alternation carrying an empty branch.
func matchGlobs(s string, globs []string) bool {
	value := flattenGlobPath(s)
	for _, pattern := range globs {
		if doublestar.MatchUnvalidated(flattenGlobPath(pattern), value) {
			return true
		}
	}
	return false
}

// filterMetrics drops metrics whose CN or issuer matches the exclude globs.
func filterMetrics(metrics []certMetric, excludeCNGlobs, excludeIssuerGlobs []string) []certMetric {
	if len(excludeCNGlobs) == 0 && len(excludeIssuerGlobs) == 0 {
		return metrics
	}
	filtered := make([]certMetric, 0, len(metrics))
	for _, m := range metrics {
		if len(excludeCNGlobs) > 0 && matchGlobs(m.cn, excludeCNGlobs) {
			continue
		}
		if len(excludeIssuerGlobs) > 0 && matchGlobs(m.issuer, excludeIssuerGlobs) {
			continue
		}
		filtered = append(filtered, m)
	}
	return filtered
}
