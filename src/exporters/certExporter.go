package exporters

import (
	"github.com/joe-elliott/cert-exporter/src/metrics"
)

type CertExporter struct {

}

func (c CertExporter) ExportMetrics(file string) error {

	duration, err := secondsToExpiryFromCertAsFile(file)

	if err != nil {
		return err
	}

	metrics.CertExpirySeconds.WithLabelValues(file).Set(duration)
	return nil
}