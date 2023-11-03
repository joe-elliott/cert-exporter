package exporters

import (
	"github.com/joe-elliott/cert-exporter/src/metrics"
)

// SecretExporter exports PEM file certs
type SecretExporter struct {
}

// ExportMetrics exports the provided PEM file
func (c *SecretExporter) ExportMetrics(bytes []byte, keyName, secretName, secretNamespace string, labels map[string]string) error {
	metricCollection, err := secondsToExpiryFromCertAsBytes(bytes)
	if err != nil {
		return err
	}

	serviceline := labels["serviceline"]

	for _, metric := range metricCollection {
		metrics.SecretExpirySeconds.WithLabelValues(keyName, metric.issuer, metric.cn, secretName, secretNamespace, serviceline).Set(metric.durationUntilExpiry)
		metrics.SecretNotAfterTimestamp.WithLabelValues(keyName, metric.issuer, metric.cn, secretName, secretNamespace, serviceline).Set(metric.notAfter)
	}

	return nil
}

func (c *SecretExporter) ResetMetrics() {
	metrics.SecretExpirySeconds.Reset()
	metrics.SecretNotAfterTimestamp.Reset()
}
