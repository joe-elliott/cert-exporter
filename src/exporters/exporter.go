package exporters

type Exporter interface {
	ExportMetrics(file string) error
}