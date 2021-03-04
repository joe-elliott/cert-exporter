package exporters

import (
	"github.com/hakhundov/cert-exporter/src/metrics"
)

// AwsExporter exports AWS PEM file certs
type AwsExporter struct {
}

// ExportMetrics exports the provided PEM file
func (c *AwsExporter) ExportMetrics(file, env string) error {
	metricCollection, err := secondsToExpiryFromCertAsBase64String(file)
	if err != nil {
		return err
	}

	for _, metric := range metricCollection {
		metrics.AwsCertExpirySeconds.WithLabelValues(file, metric.issuer, metric.cn).Set(metric.durationUntilExpiry)
	}

	return nil
}
