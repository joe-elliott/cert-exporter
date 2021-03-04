package exporters

import (
	"github.com/hakhundov/cert-exporter/src/metrics"
)

// CertExporter exports PEM file certs
type CertExporter struct {
}

// ExportMetrics exports the provided PEM file
func (c *CertExporter) ExportMetrics(file, nodeName string) error {
	metricCollection, err := secondsToExpiryFromCertAsFile(file)
	if err != nil {
		return err
	}

	for _, metric := range metricCollection {
		metrics.CertExpirySeconds.WithLabelValues(file, metric.issuer, metric.cn, nodeName).Set(metric.durationUntilExpiry)
		metrics.CertNotAfterTimestamp.WithLabelValues(file, metric.issuer, metric.cn, nodeName).Set(metric.notAfter)
	}

	return nil
}