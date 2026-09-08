package exporters

import (
	"github.com/joe-elliott/cert-exporter/src/metrics"
)

// AwsExporter exports AWS PEM file certs
type AwsExporter struct {
	ExcludeCNGlobs     []string
	ExcludeIssuerGlobs []string
}

// ExportMetrics exports the provided PEM file
func (c *AwsExporter) ExportMetrics(file, secretName, key string) error {
	metricCollection, err := secondsToExpiryFromCertAsBase64String(file)
	if err != nil {
		return err
	}
	metricCollection = filterMetrics(metricCollection, c.ExcludeCNGlobs, c.ExcludeIssuerGlobs)

	for _, metric := range metricCollection {
		labels := metrics.AppendSerial([]string{secretName, key, file, metric.issuer, metric.cn}, metric.serial)
		metrics.AwsCertExpirySeconds.WithLabelValues(labels...).Set(metric.durationUntilExpiry)
	}

	return nil
}

func (c *AwsExporter) ResetMetrics() {
	metrics.AwsCertExpirySeconds.Reset()
}
