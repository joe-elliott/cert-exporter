package exporters

import (
	"github.com/joe-elliott/cert-exporter/src/metrics"
)

// ConfigMapExporter exports PEM file certs
type ConfigMapExporter struct {
}

// ExportMetrics exports the provided PEM file
func (c *ConfigMapExporter) ExportMetrics(bytes []byte, keyName, configMapName, configMapNamespace string) error {
	metricCollection, err := secondsToExpiryFromCertAsBytes(bytes, "")
	if err != nil {
		return err
	}

	for _, metric := range metricCollection {
		metrics.ConfigMapExpirySeconds.WithLabelValues(keyName, metric.issuer, metric.cn, configMapName, configMapNamespace).Set(metric.durationUntilExpiry)
		metrics.ConfigMapNotAfterTimestamp.WithLabelValues(keyName, metric.issuer, metric.cn, configMapName, configMapNamespace).Set(metric.notAfter)
	}

	return nil
}

func (c *ConfigMapExporter) ResetMetrics() {
	metrics.ConfigMapExpirySeconds.Reset()
	metrics.ConfigMapNotAfterTimestamp.Reset()
}
