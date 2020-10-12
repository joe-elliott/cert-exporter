package exporters

import (
	"fmt"
	"time"

	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
)

type certMetric struct {
	durationUntilExpiry float64
	notAfter            float64
	issuer              string
	cn                  string
}

func secondsToExpiryFromCertAsFile(file string, includeFullCertChain bool) ([]certMetric, error) {
	certBytes, err := ioutil.ReadFile(file)
	if err != nil {
		return []certMetric{}, err
	}

	return secondsToExpiryFromCertAsBytes(certBytes, includeFullCertChain)
}

func secondsToExpiryFromCertAsBase64String(s string, includeFullCertChain bool) ([]certMetric, error) {
	certBytes, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return []certMetric{}, err
	}

	return secondsToExpiryFromCertAsBytes(certBytes, includeFullCertChain)
}

func secondsToExpiryFromCertAsBytes(certBytes []byte, includeFullCertChain bool) ([]certMetric, error) {
	var metrics []certMetric
	var blocks []*pem.Block

	block, rest := pem.Decode(certBytes)
	if block == nil {
		return metrics, fmt.Errorf("Failed to parse as a pem")
	}
	blocks = append(blocks, block)

	// If the include-full-cert-chain flag is used, the rest of the bytes in the file will also be processed
	if includeFullCertChain {
		for len(rest) != 0 {
			block, rest = pem.Decode(rest)
			if block == nil {
				return metrics, fmt.Errorf("Failed to parse intermediate as a pem")
			}
			if block.Type == "CERTIFICATE" {
				blocks = append(blocks, block)
			}
		}
	}

	for _, block := range blocks {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return metrics, err
		}

		var metric certMetric
		metric.notAfter = float64(cert.NotAfter.Unix())
		metric.durationUntilExpiry = time.Until(cert.NotAfter).Seconds()
		metric.issuer = cert.Issuer.CommonName
		metric.cn = cert.Subject.CommonName

		metrics = append(metrics, metric)
	}

	return metrics, nil
}
