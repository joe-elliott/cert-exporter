package exporters

import (
	dto "github.com/prometheus/client_model/go"
)

// getLabelMap is a test helper function that converts prometheus metric labels to a map
func getLabelMap(metric *dto.Metric) map[string]string {
	labels := make(map[string]string)
	for _, label := range metric.GetLabel() {
		labels[label.GetName()] = label.GetValue()
	}
	return labels
}
