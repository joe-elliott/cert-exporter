package exporters

import (
	"github.com/joe-elliott/cert-exporter/src/metrics"
)

// CertExporter exports PEM file certs
type SecretExporter struct {
}

// ExportMetrics exports the provided PEM file
func (c *SecretExporter) ExportMetrics(bytes []byte, keyName, secretName, secretNamespace string) error {
	metric, err := secondsToExpiryFromCertAsBytes(bytes)
	if err != nil {
		return err
	}

	metrics.SecretExpirySeconds.WithLabelValues(keyName, metric.cn, metric.subject, metric.subjectSAN, metric.issuer, secretName, secretNamespace).Set(metric.durationUntilExpiry)
	metrics.SecretNotAfterTimestamp.WithLabelValues(keyName, metric.cn, metric.subject, metric.subjectSAN, metric.issuer, secretName, secretNamespace).Set(metric.notAfter)
	return nil
}
