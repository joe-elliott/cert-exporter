package exporters

import (
	"github.com/hakhundov/cert-exporter/src/metrics"
)

// CertExporter exports PEM file certs
type SecretExporter struct {
}

// ExportMetrics exports the provided PEM file
func (c *SecretExporter) ExportMetrics(bytes []byte, keyName, secretName, secretNamespace string) error {
	metricCollection, err := secondsToExpiryFromCertAsBytes(bytes)
	if err != nil {
		return err
	}

	for _, metric := range metricCollection {
		metrics.SecretExpirySeconds.WithLabelValues(keyName, metric.issuer, metric.cn, secretName, secretNamespace).Set(metric.durationUntilExpiry)
		metrics.SecretNotAfterTimestamp.WithLabelValues(keyName, metric.issuer, metric.cn, secretName, secretNamespace).Set(metric.notAfter)
	}

	return nil
}
