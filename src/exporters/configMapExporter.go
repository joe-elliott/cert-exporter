package exporters

import (
	"github.com/joe-elliott/cert-exporter/src/metrics"
)

// ConfigMapExporter exports PEM file certs
type ConfigMapExporter struct {
	ExcludeCNGlobs     []string
	ExcludeIssuerGlobs []string
}

// ExportMetrics exports the provided PEM file
func (c *ConfigMapExporter) ExportMetrics(bytes []byte, keyName, configMapName, configMapNamespace string) error {
	metricCollection, err := secondsToExpiryFromCertAsBytes(bytes, "")
	if err != nil {
		return err
	}
	metricCollection = filterMetrics(metricCollection, c.ExcludeCNGlobs, c.ExcludeIssuerGlobs)

	for _, metric := range metricCollection {
		labels := metrics.AppendSerial([]string{keyName, metric.issuer, metric.cn, configMapName, configMapNamespace}, metric.serial)
		metrics.ConfigMapExpirySeconds.WithLabelValues(labels...).Set(metric.durationUntilExpiry)
		metrics.ConfigMapNotAfterTimestamp.WithLabelValues(labels...).Set(metric.notAfter)
		metrics.ConfigMapNotBeforeTimestamp.WithLabelValues(labels...).Set(metric.notBefore)
	}

	return nil
}

func (c *ConfigMapExporter) ResetMetrics() {
	metrics.ConfigMapExpirySeconds.Reset()
	metrics.ConfigMapNotAfterTimestamp.Reset()
	metrics.ConfigMapNotBeforeTimestamp.Reset()
}
