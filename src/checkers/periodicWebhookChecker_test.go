package checkers

import (
	"testing"
	"time"

	"github.com/joe-elliott/cert-exporter/src/exporters"
)

func TestNewWebhookChecker(t *testing.T) {
	period := 5 * time.Minute
	labelSelectors := []string{"app=webhook"}
	annotationSelectors := []string{"webhook.cert-manager.io/inject-ca-from"}
	kubeconfigPath := "/path/to/kubeconfig"
	exporter := &exporters.WebhookExporter{}

	checker := NewWebhookChecker(period, labelSelectors, annotationSelectors, kubeconfigPath, exporter)

	if checker == nil {
		t.Fatal("Expected NewWebhookChecker to return non-nil checker")
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

	if checker.kubeconfigPath != kubeconfigPath {
		t.Errorf("Expected kubeconfigPath '%s', got '%s'", kubeconfigPath, checker.kubeconfigPath)
	}

	if checker.exporter != exporter {
		t.Error("Expected exporter to match provided exporter")
	}
}

func TestNewWebhookChecker_EmptyParameters(t *testing.T) {
	checker := NewWebhookChecker(time.Second, []string{}, []string{}, "", nil)

	if checker == nil {
		t.Fatal("Expected NewWebhookChecker to return non-nil checker")
	}

	if len(checker.labelSelectors) != 0 {
		t.Error("Expected empty labelSelectors")
	}

	if len(checker.annotationSelectors) != 0 {
		t.Error("Expected empty annotationSelectors")
	}
}

func TestNewWebhookChecker_MultipleSelectors(t *testing.T) {
	labelSelectors := []string{"label1", "label2", "label3"}
	annotationSelectors := []string{"ann1", "ann2"}

	checker := NewWebhookChecker(
		10*time.Second,
		labelSelectors,
		annotationSelectors,
		"/etc/kubeconfig",
		&exporters.WebhookExporter{},
	)

	if len(checker.labelSelectors) != len(labelSelectors) {
		t.Errorf("Expected %d labelSelectors, got %d", len(labelSelectors), len(checker.labelSelectors))
	}

	if len(checker.annotationSelectors) != len(annotationSelectors) {
		t.Errorf("Expected %d annotationSelectors, got %d", len(annotationSelectors), len(checker.annotationSelectors))
	}

	for i, selector := range labelSelectors {
		if checker.labelSelectors[i] != selector {
			t.Errorf("Expected labelSelector[%d] = '%s', got '%s'", i, selector, checker.labelSelectors[i])
		}
	}
}
