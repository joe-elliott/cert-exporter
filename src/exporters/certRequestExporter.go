package exporters

import (
	"github.com/joe-elliott/cert-exporter/src/metrics"
)

// CertRequestExporter exports PEM file certs
type CertRequestExporter struct {
}

// ExportMetrics exports the provided PEM file
func (c *CertRequestExporter) ExportMetrics(bytes []byte, certrequest, certrequestNamespace string) error {
	metricCollection, err := secondsToExpiryFromCertAsBytes(bytes)
	if err != nil {
		return err
	}

	for _, metric := range metricCollection {
		metrics.CertRequestExpirySeconds.WithLabelValues( metric.issuer, metric.cn, certrequest, certrequestNamespace).Set(metric.durationUntilExpiry)
		metrics.CertRequestNotAfterTimestamp.WithLabelValues(metric.issuer, metric.cn, certrequest, certrequestNamespace).Set(metric.notAfter)
	}

	return nil
}

func (c *CertRequestExporter) ResetMetrics() {
	metrics.SecretExpirySeconds.Reset()
	metrics.SecretNotAfterTimestamp.Reset()
}
