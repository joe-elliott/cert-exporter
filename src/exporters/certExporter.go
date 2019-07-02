package exporters

import (
	"fmt"
	"io/ioutil"
	"time"

	"crypto/x509"
	"encoding/pem"

	"github.com/joe-elliott/cert-exporter/src/metrics"
)

type CertExporter struct {

}

func (c CertExporter) ExportMetrics(file string) error {

	certBytes, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(certBytes)
	if block == nil {
		return fmt.Errorf("Failed to parse %v as a pem", file)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	durationUntilExpiry := time.Until(cert.NotAfter)
	metrics.CertExpirySeconds.WithLabelValues(file).Set(durationUntilExpiry.Seconds())

	return nil
}