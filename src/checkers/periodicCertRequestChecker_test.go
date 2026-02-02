package checkers

import (
	"testing"
	"time"

	"github.com/joe-elliott/cert-exporter/src/exporters"
)

func TestNewCertRequestChecker(t *testing.T) {
	period := 5 * time.Minute
	labelSelectors := []string{"app=test", "env=prod"}
	annotationSelectors := []string{"cert-manager.io/certificate-name"}
	namespaces := []string{"default", "kube-system"}
	kubeconfigPath := "/path/to/kubeconfig"
	exporter := &exporters.CertRequestExporter{}

	checker := NewCertRequestChecker(period, labelSelectors, annotationSelectors, namespaces, kubeconfigPath, exporter)

	if checker == nil {
		t.Fatal("Expected NewCertRequestChecker to return non-nil checker")
	}

	if checker.period != period {
		t.Errorf("Expected period %v, got %v", period, checker.period)
	}

	if len(checker.labelSelectors) != len(labelSelectors) {
		t.Errorf("Expected %d labelSelectors, got %d", len(labelSelectors), len(checker.labelSelectors))
	}

	if len(checker.annotationSelectors) != len(annotationSelectors) {
		t.Errorf("Expected %d annotationSelectors, got %d", len(annotationSelectors), len(checker.annotationSelectors))
	}

	if len(checker.namespaces) != len(namespaces) {
		t.Errorf("Expected %d namespaces, got %d", len(namespaces), len(checker.namespaces))
	}

	if checker.kubeconfigPath != kubeconfigPath {
		t.Errorf("Expected kubeconfigPath '%s', got '%s'", kubeconfigPath, checker.kubeconfigPath)
	}

	if checker.exporter != exporter {
		t.Error("Expected exporter to match provided exporter")
	}
}

func TestNewCertRequestChecker_EmptyParameters(t *testing.T) {
	checker := NewCertRequestChecker(time.Second, []string{}, []string{}, []string{}, "", nil)

	if checker == nil {
		t.Fatal("Expected NewCertRequestChecker to return non-nil checker")
	}

	if len(checker.labelSelectors) != 0 {
		t.Error("Expected empty labelSelectors")
	}

	if len(checker.annotationSelectors) != 0 {
		t.Error("Expected empty annotationSelectors")
	}

	if len(checker.namespaces) != 0 {
		t.Error("Expected empty namespaces")
	}
}

func TestNewCertRequestChecker_MultipleValues(t *testing.T) {
	labelSelectors := []string{"label1", "label2", "label3"}
	annotationSelectors := []string{"ann1", "ann2"}
	namespaces := []string{"ns1", "ns2", "ns3", "ns4"}

	checker := NewCertRequestChecker(
		10*time.Second,
		labelSelectors,
		annotationSelectors,
		namespaces,
		"/etc/kubeconfig",
		&exporters.CertRequestExporter{},
	)

	if len(checker.labelSelectors) != len(labelSelectors) {
		t.Errorf("Expected %d labelSelectors, got %d", len(labelSelectors), len(checker.labelSelectors))
	}

	if len(checker.annotationSelectors) != len(annotationSelectors) {
		t.Errorf("Expected %d annotationSelectors, got %d", len(annotationSelectors), len(checker.annotationSelectors))
	}

	if len(checker.namespaces) != len(namespaces) {
		t.Errorf("Expected %d namespaces, got %d", len(namespaces), len(checker.namespaces))
	}
}
