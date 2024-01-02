package exporters

import (
	"fmt"
	"time"

	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"

	"software.sslmate.com/src/go-pkcs12"
)

type certMetric struct {
	durationUntilExpiry float64
	notAfter            float64
	issuer              string
	cn                  string
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

	parsed, metrics, err := parseAsPEM(certBytes)
	if parsed {
		return metrics, err
	}
	// Parse as PKCS ?
	parsed, metrics, err = parseAsPKCS(certBytes, certPassword)
	if parsed {
		return metrics, nil
	}
	return nil, fmt.Errorf("failed to parse as pem and pkcs12: %w", err)
}

func getCertificateMetrics(cert *x509.Certificate) certMetric {
	var metric certMetric
	metric.notAfter = float64(cert.NotAfter.Unix())
	metric.durationUntilExpiry = time.Until(cert.NotAfter).Seconds()
	metric.issuer = cert.Issuer.CommonName
	metric.cn = cert.Subject.CommonName
	return metric
}

func parseAsPKCS(certBytes []byte, certPassword string) (bool, []certMetric, error) {
	var metrics []certMetric
	var blocks []*pem.Block
	var last_err error

	pfx_blocks, err := pkcs12.ToPEM(certBytes, certPassword)
	if err != nil {
		return false, nil, err
	}
	for _, b := range pfx_blocks {
		if b.Type == "CERTIFICATE" {
			blocks = append(blocks, b)
		}
	}

	for _, block := range blocks {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			var metric = getCertificateMetrics(cert)
			metrics = append(metrics, metric)
		} else {
			last_err = err
		}
	}
	return true, metrics, last_err
}

func parseAsPEM(certBytes []byte) (bool, []certMetric, error) {
	var metrics []certMetric
	var blocks []*pem.Block

	block, rest := pem.Decode(certBytes)
	if block == nil {
		return false, metrics, fmt.Errorf("Failed to parse as a pem")
	}
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
		var metric = getCertificateMetrics(cert)
		metrics = append(metrics, metric)
	}
	return true, metrics, nil
}
