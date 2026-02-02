package checkers

import (
	"testing"
	"time"

	"github.com/joe-elliott/cert-exporter/src/exporters"
)

// Placeholder test - real Kubernetes integration tests are in integration_test.go
func TestPeriodicSecretChecker_Constructor(t *testing.T) {
	checker := NewSecretChecker(
		0,
		[]string{"app=test"},
		[]string{"*.crt"},
		[]string{},
		[]string{"annotation=test"},
		[]string{"default"},
		[]string{},
		"",
		nil,
		[]string{},
	)

	if checker == nil {
		t.Fatal("Expected non-nil checker")
	}

	if len(checker.labelSelectors) != 1 {
		t.Errorf("Expected 1 label selector, got %d", len(checker.labelSelectors))
	}

	if checker.labelSelectors[0] != "app=test" {
		t.Errorf("Expected label selector 'app=test', got '%s'", checker.labelSelectors[0])
	}

	if len(checker.includeSecretsDataGlobs) != 1 {
		t.Errorf("Expected 1 include glob, got %d", len(checker.includeSecretsDataGlobs))
	}

	if len(checker.annotationSelectors) != 1 {
		t.Errorf("Expected 1 annotation selector, got %d", len(checker.annotationSelectors))
	}

	if len(checker.namespaces) != 1 {
		t.Errorf("Expected 1 namespace, got %d", len(checker.namespaces))
	}
}

func TestNewSecretChecker_FullParameters(t *testing.T) {
	period := 5 * time.Second
	labelSelectors := []string{"app=test", "tier=frontend"}
	includeGlobs := []string{"*.crt", "*.pem"}
	excludeGlobs := []string{"*.key"}
	annotationSelectors := []string{"cert-manager.io/certificate-name"}
	namespaces := []string{"default", "test"}
	nsLabelSelector := []string{"env=prod"}
	kubeconfigPath := "/path/to/kubeconfig"
	exporter := &exporters.SecretExporter{}
	includeTypes := []string{"kubernetes.io/tls"}

	checker := NewSecretChecker(
		period,
		labelSelectors,
		includeGlobs,
		excludeGlobs,
		annotationSelectors,
		namespaces,
		nsLabelSelector,
		kubeconfigPath,
		exporter,
		includeTypes,
	)

	if checker == nil {
		t.Fatal("Expected NewSecretChecker to return non-nil checker")
	}

	if checker.period != period {
		t.Errorf("Expected period %v, got %v", period, checker.period)
	}

	if len(checker.labelSelectors) != len(labelSelectors) {
		t.Errorf("Expected %d labelSelectors, got %d", len(labelSelectors), len(checker.labelSelectors))
	}

	if len(checker.includeSecretsDataGlobs) != len(includeGlobs) {
		t.Errorf("Expected %d includeSecretsDataGlobs, got %d", len(includeGlobs), len(checker.includeSecretsDataGlobs))
	}

	if len(checker.excludeSecretsDataGlobs) != len(excludeGlobs) {
		t.Errorf("Expected %d excludeSecretsDataGlobs, got %d", len(excludeGlobs), len(checker.excludeSecretsDataGlobs))
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
		t.Errorf("Expected kubeconfigPath %s, got %s", kubeconfigPath, checker.kubeconfigPath)
	}

	if checker.exporter != exporter {
		t.Error("Expected exporter to match provided exporter")
	}

	if len(checker.includeSecretsTypes) != len(includeTypes) {
		t.Errorf("Expected %d includeSecretsTypes, got %d", len(includeTypes), len(checker.includeSecretsTypes))
	}
}

func TestNewSecretChecker_EmptyParameters(t *testing.T) {
	checker := NewSecretChecker(
		time.Second,
		[]string{},
		[]string{},
		[]string{},
		[]string{},
		[]string{},
		[]string{},
		"",
		&exporters.SecretExporter{},
		[]string{},
	)

	if checker == nil {
		t.Fatal("Expected NewSecretChecker to return non-nil checker even with empty parameters")
	}

	if len(checker.labelSelectors) != 0 {
		t.Error("Expected empty labelSelectors")
	}

	if len(checker.includeSecretsDataGlobs) != 0 {
		t.Error("Expected empty includeSecretsDataGlobs")
	}

	if len(checker.namespaces) != 0 {
		t.Error("Expected empty namespaces")
	}
}
