package exporters

import (
	"github.com/joe-elliott/cert-exporter/src/metrics"
)

// CertExporter exports PEM file certs
type CertExporter struct {
	// Password unlocks password-protected keystore files (PKCS#12, JKS).
	Password string
}

// ExportMetrics exports the provided PEM file
func (c *CertExporter) ExportMetrics(file, nodeName string) error {
	metricCollection, err := secondsToExpiryFromCertAsFile(file, c.Password)
	if err != nil {
		return err
	}

	for _, metric := range metricCollection {
		labels := metrics.AppendSerial([]string{file, metric.issuer, metric.cn, nodeName}, metric.serial)
		metrics.CertExpirySeconds.WithLabelValues(labels...).Set(metric.durationUntilExpiry)
		metrics.CertNotAfterTimestamp.WithLabelValues(labels...).Set(metric.notAfter)
		metrics.CertNotBeforeTimestamp.WithLabelValues(labels...).Set(metric.notBefore)
	}

	return nil
}

func (c *CertExporter) ResetMetrics() {
	metrics.CertExpirySeconds.Reset()
	metrics.CertNotAfterTimestamp.Reset()
	metrics.CertNotBeforeTimestamp.Reset()
}
