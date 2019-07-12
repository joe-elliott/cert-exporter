package exporters

// CertExporter exports PEM file certs
type SecretExporter struct {
}

// ExportMetrics exports the provided PEM file
func (c SecretExporter) ExportMetrics(secret string) error {

	return nil
}
