package checkers

import (
	"testing"
	"time"

	"github.com/joe-elliott/cert-exporter/src/exporters"
)

func TestNewConfigMapChecker(t *testing.T) {
	period := 5 * time.Minute
	labelSelectors := []string{"app=test"}
	includeGlobs := []string{"*.crt", "*.pem"}
	excludeGlobs := []string{"*.key"}
	annotationSelectors := []string{"annotation"}
	namespaces := []string{"default"}
	nsLabelSelector := []string{"env=prod"}
	kubeconfigPath := "/path/to/kubeconfig"
	exporter := &exporters.ConfigMapExporter{}

	checker := NewConfigMapChecker(
		period,
		labelSelectors,
		includeGlobs,
		excludeGlobs,
		annotationSelectors,
		namespaces,
		nsLabelSelector,
		kubeconfigPath,
		exporter,
	)

	if checker == nil {
		t.Fatal("Expected NewConfigMapChecker to return non-nil checker")
	}

	if checker.period != period {
		t.Errorf("Expected period %v, got %v", period, checker.period)
	}

	if len(checker.labelSelectors) != len(labelSelectors) {
		t.Errorf("Expected %d labelSelectors, got %d", len(labelSelectors), len(checker.labelSelectors))
	}

	if len(checker.includeConfigMapsDataGlobs) != len(includeGlobs) {
		t.Errorf("Expected %d includeConfigMapsDataGlobs, got %d", len(includeGlobs), len(checker.includeConfigMapsDataGlobs))
	}

	if len(checker.excludeConfigMapsDataGlobs) != len(excludeGlobs) {
		t.Errorf("Expected %d excludeConfigMapsDataGlobs, got %d", len(excludeGlobs), len(checker.excludeConfigMapsDataGlobs))
	}

	if len(checker.annotationSelectors) != len(annotationSelectors) {
		t.Errorf("Expected %d annotationSelectors, got %d", len(annotationSelectors), len(checker.annotationSelectors))
	}

	if len(checker.namespaces) != len(namespaces) {
		t.Errorf("Expected %d namespaces, got %d", len(namespaces), len(checker.namespaces))
	}

	if len(checker.nsLabelSelector) != len(nsLabelSelector) {
		t.Errorf("Expected %d nsLabelSelector, got %d", len(nsLabelSelector), len(checker.nsLabelSelector))
	}

	if checker.kubeconfigPath != kubeconfigPath {
		t.Errorf("Expected kubeconfigPath '%s', got '%s'", kubeconfigPath, checker.kubeconfigPath)
	}

	if checker.exporter != exporter {
		t.Error("Expected exporter to match provided exporter")
	}
}

func TestNewConfigMapChecker_EmptyParameters(t *testing.T) {
	checker := NewConfigMapChecker(
		time.Second,
		[]string{},
		[]string{},
		[]string{},
		[]string{},
		[]string{},
		[]string{},
		"",
		nil,
	)

	if checker == nil {
		t.Fatal("Expected NewConfigMapChecker to return non-nil checker")
	}

	if len(checker.labelSelectors) != 0 {
		t.Error("Expected empty labelSelectors")
	}

	if len(checker.includeConfigMapsDataGlobs) != 0 {
		t.Error("Expected empty includeConfigMapsDataGlobs")
	}

	if len(checker.namespaces) != 0 {
		t.Error("Expected empty namespaces")
	}
}

func TestNewConfigMapChecker_MultipleValues(t *testing.T) {
	labelSelectors := []string{"label1", "label2"}
	includeGlobs := []string{"*.crt", "*.pem", "ca-bundle.crt"}
	excludeGlobs := []string{"*.key", "*.tmp"}
	annotationSelectors := []string{"ann1", "ann2", "ann3"}
	namespaces := []string{"ns1", "ns2", "ns3"}
	nsLabelSelector := []string{"env=prod", "env=staging"}

	checker := NewConfigMapChecker(
		30*time.Second,
		labelSelectors,
		includeGlobs,
		excludeGlobs,
		annotationSelectors,
		namespaces,
		nsLabelSelector,
		"/etc/kubernetes/admin.conf",
		&exporters.ConfigMapExporter{},
	)

	if len(checker.labelSelectors) != len(labelSelectors) {
		t.Errorf("Expected %d labelSelectors, got %d", len(labelSelectors), len(checker.labelSelectors))
	}

	if len(checker.includeConfigMapsDataGlobs) != len(includeGlobs) {
		t.Errorf("Expected %d includeGlobs, got %d", len(includeGlobs), len(checker.includeConfigMapsDataGlobs))
	}

	if len(checker.excludeConfigMapsDataGlobs) != len(excludeGlobs) {
		t.Errorf("Expected %d excludeGlobs, got %d", len(excludeGlobs), len(checker.excludeConfigMapsDataGlobs))
	}
}
