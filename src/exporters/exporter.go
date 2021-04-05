package exporters

// Exporter is an interface for objects that export cert information
type Exporter interface {
	ExportMetrics(file, nodeName string) error
	ResetMetrics()
}
