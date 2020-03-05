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
}

func secondsToExpiryFromCertAsFile(file string) (certMetric, error) {

	certBytes, err := ioutil.ReadFile(file)
	if err != nil {
		return certMetric{}, err
	}

	return secondsToExpiryFromCertAsBytes(certBytes)
}

func secondsToExpiryFromCertAsBase64String(s string) (certMetric, error) {
	certBytes, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return certMetric{}, err
	}

	return secondsToExpiryFromCertAsBytes(certBytes)
}

func secondsToExpiryFromCertAsBytes(certBytes []byte) (certMetric, error) {
	var metric certMetric
	block, _ := pem.Decode(certBytes)
	if block == nil {
		return metric, fmt.Errorf("Failed to parse as a pem")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return metric, err
	}

	metric.notAfter = float64(cert.NotAfter.Unix())
	durationUntilExpiry := time.Until(cert.NotAfter)
	metric.durationUntilExpiry = durationUntilExpiry.Seconds()
	return metric, nil
}
