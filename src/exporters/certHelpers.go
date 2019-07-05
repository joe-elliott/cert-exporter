package exporters

import (
	"fmt"
	"time"

	"io/ioutil"
	"crypto/x509"
	"encoding/pem"
	"encoding/base64"
)

func secondsToExpiryFromCertAsFile(file string) (float64, error) {

	certBytes, err := ioutil.ReadFile(file)
	if err != nil {
		return 0, err
	}

	return secondsToExpiryFromCertAsBytes(certBytes)
}

func secondsToExpiryFromCertAsBase64String(s string) (float64, error) {
	certBytes, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return 0, err
	}

	return secondsToExpiryFromCertAsBytes(certBytes)
}

func secondsToExpiryFromCertAsBytes(certBytes []byte) (float64, error) {
	block, _ := pem.Decode(certBytes)
	if block == nil {
		return 0, fmt.Errorf("Failed to parse as a pem")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return 0, err
	}

	durationUntilExpiry := time.Until(cert.NotAfter)
	return durationUntilExpiry.Seconds(), nil
}