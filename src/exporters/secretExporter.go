package exporters

// CertExporter exports PEM file certs
type SecretExporter struct {
}

// ExportMetrics exports the provided PEM file
func (c *SecretExporter) ExportMetrics(secret string) error {

	_, err := secondsToExpiryFromCertAsBase64String(secret)

	if err != nil {
		return err
	}

	// jpe -metrics.CertExpirySeconds.WithLabelValues(file).Set(duration)
	return nil
}
