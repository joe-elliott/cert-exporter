package exporters

import (
	"github.com/joe-elliott/cert-exporter/src/metrics"
)

// WebhookExporter exports PEM file certs
type WebhookExporter struct {
	ExcludeCNGlobs     []string
	ExcludeIssuerGlobs []string
}

// ExportMetrics exports the provided PEM file
func (c *WebhookExporter) ExportMetrics(bytes []byte, typeName, webhookName, admissionReviewVersionName string) error {
	metricCollection, err := secondsToExpiryFromCertAsBytes(bytes, "")
	if err != nil {
		return err
	}
	metricCollection = filterMetrics(metricCollection, c.ExcludeCNGlobs, c.ExcludeIssuerGlobs)

	for _, metric := range metricCollection {
		labels := metrics.AppendSerial([]string{typeName, metric.issuer, metric.cn, webhookName, admissionReviewVersionName}, metric.serial)
		metrics.WebhookExpirySeconds.WithLabelValues(labels...).Set(metric.durationUntilExpiry)
		metrics.WebhookNotAfterTimestamp.WithLabelValues(labels...).Set(metric.notAfter)
		metrics.WebhookNotBeforeTimestamp.WithLabelValues(labels...).Set(metric.notBefore)
	}

	return nil
}

func (c *WebhookExporter) ResetMetrics() {
	metrics.WebhookExpirySeconds.Reset()
	metrics.WebhookNotAfterTimestamp.Reset()
	metrics.WebhookNotBeforeTimestamp.Reset()
}
