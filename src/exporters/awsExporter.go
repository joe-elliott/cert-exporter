package exporters

import (
	"github.com/joe-elliott/cert-exporter/src/metrics"
)

// AwsExporter exports AWS PEM file certs
type AwsExporter struct {
}

// ExportMetrics exports the provided PEM file
func (c *AwsExporter) ExportMetrics(file, secretName, key string) error {
	// 'file' here is actually the base64 encoded certificate string
	metricCollection, err := secondsToExpiryFromCertAsBase64String(file, "", nil, nil, nil) // Pass "" as password, no CN/Alias/Issuer specific filters for AWS certs
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
