package exporters

import (
	"fmt"
	"time"

	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"

	"golang.org/x/crypto/pkcs12"
)

type certMetric struct {
	durationUntilExpiry float64
	notAfter            float64
	issuer              string
	cn                  string
}

func secondsToExpiryFromCertAsFile(file string) ([]certMetric, error) {
	certBytes, err := ioutil.ReadFile(file)
	if err != nil {
		return []certMetric{}, err
	}

	return secondsToExpiryFromCertAsBytes(certBytes)
}

func secondsToExpiryFromCertAsBase64String(s string) ([]certMetric, error) {
	certBytes, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return []certMetric{}, err
	}

	return secondsToExpiryFromCertAsBytes(certBytes)
}

func decodeFromPKCS(certBytes []byte) ([]*pem.Block, error) {
	var blocks []*pem.Block
	pfx_blocks, err := pkcs12.ToPEM(certBytes, "")
	if err != nil {
		return nil, err
	}
	for _ , b := range pfx_blocks {
		if b.Type == "CERTIFICATE" {
			blocks = append(blocks, b)
		}
	}
	return blocks, nil
}


func secondsToExpiryFromCertAsBytes(certBytes []byte) ([]certMetric, error) {
	var metrics []certMetric
	var blocks []*pem.Block
	var last_err error

	// Export the first certificates in the certificate chain
	block, rest := pem.Decode(certBytes)
	if block != nil {
		blocks = append(blocks, block)
		// Export the remaining certificates in the certificate chain
		for len(rest) != 0 {
			block, rest = pem.Decode(rest)
			if block == nil {
				return metrics, fmt.Errorf("Failed to parse intermediate as a pem")
			}
			if block.Type == "CERTIFICATE" {
				blocks = append(blocks, block)
			}
		}
	} else {
		// Parse as PKCS ?
		pfx_blocks, err := decodeFromPKCS(certBytes)
		if err != nil {
			return metrics, fmt.Errorf("failed to parse as pem and pkcs12")
		}
		blocks = pfx_blocks	
	}

	for _, block := range blocks {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			var metric certMetric
			metric.notAfter = float64(cert.NotAfter.Unix())
			metric.durationUntilExpiry = time.Until(cert.NotAfter).Seconds()
			metric.issuer = cert.Issuer.CommonName
			metric.cn = cert.Subject.CommonName

			metrics = append(metrics, metric)
		} else {
			last_err = err
		}
	}

	if len(metrics) == 0 {
		return metrics, last_err
	}

	return metrics, nil
}
