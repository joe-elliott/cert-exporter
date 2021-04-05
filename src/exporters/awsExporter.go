package exporters

import (
	"github.com/joe-elliott/cert-exporter/src/metrics"
)

// AwsExporter exports AWS PEM file certs
type AwsExporter struct {
}

// ExportMetrics exports the provided PEM file
func (c *AwsExporter) ExportMetrics(file, secretName, key string) error {
	metricCollection, err := secondsToExpiryFromCertAsBase64String(file)
	if err != nil {
		return err
	}

	for _, metric := range metricCollection {
		metrics.AwsCertExpirySeconds.WithLabelValues(secretName, key, file, metric.issuer, metric.cn).Set(metric.durationUntilExpiry)
	}

	return nil
}

func (c *AwsExporter) ResetMetrics() {
	metrics.AwsCertExpirySeconds.Reset()
}