package exporters

import (
	"github.com/joe-elliott/cert-exporter/src/metrics"
)

// CertRequestExporter exports PEM file certs
type CertRequestExporter struct {
	ExcludeCNGlobs     []string
	ExcludeIssuerGlobs []string
}

// ExportMetrics exports the provided PEM file
func (c *CertRequestExporter) ExportMetrics(bytes []byte, certrequest, certrequestNamespace string) error {
	metricCollection, err := secondsToExpiryFromCertAsBytes(bytes, "")
	if err != nil {
		return err
	}
	metricCollection = filterMetrics(metricCollection, c.ExcludeCNGlobs, c.ExcludeIssuerGlobs)

	for _, metric := range metricCollection {
		labels := metrics.AppendSerial([]string{metric.issuer, metric.cn, certrequest, certrequestNamespace}, metric.serial)
		metrics.CertRequestExpirySeconds.WithLabelValues(labels...).Set(metric.durationUntilExpiry)
		metrics.CertRequestNotAfterTimestamp.WithLabelValues(labels...).Set(metric.notAfter)
		metrics.CertRequestNotBeforeTimestamp.WithLabelValues(labels...).Set(metric.notBefore)
	}

	return nil
}

func (c *CertRequestExporter) ResetMetrics() {
	metrics.CertRequestExpirySeconds.Reset()
	metrics.CertRequestNotAfterTimestamp.Reset()
	metrics.CertRequestNotBeforeTimestamp.Reset()
}
