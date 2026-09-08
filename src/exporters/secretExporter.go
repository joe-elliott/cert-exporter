package exporters

import (
	"github.com/joe-elliott/cert-exporter/src/metrics"
)

// SecretExporter exports PEM file certs
type SecretExporter struct {
	ExcludeCNGlobs     []string
	ExcludeIssuerGlobs []string
}

// ExportMetrics exports the provided PEM file
func (c *SecretExporter) ExportMetrics(bytes []byte, keyName, secretName, secretNamespace, certPassword string) error {
	metricCollection, err := secondsToExpiryFromCertAsBytes(bytes, certPassword)
	if err != nil {
		return err
	}
	metricCollection = filterMetrics(metricCollection, c.ExcludeCNGlobs, c.ExcludeIssuerGlobs)

	for _, metric := range metricCollection {
		labels := metrics.AppendSerial([]string{keyName, metric.issuer, metric.cn, secretName, secretNamespace}, metric.serial)
		metrics.SecretExpirySeconds.WithLabelValues(labels...).Set(metric.durationUntilExpiry)
		metrics.SecretNotAfterTimestamp.WithLabelValues(labels...).Set(metric.notAfter)
		metrics.SecretNotBeforeTimestamp.WithLabelValues(labels...).Set(metric.notBefore)
	}

	return nil
}

func (c *SecretExporter) ResetMetrics() {
	metrics.SecretExpirySeconds.Reset()
	metrics.SecretNotAfterTimestamp.Reset()
	metrics.SecretNotBeforeTimestamp.Reset()
}
