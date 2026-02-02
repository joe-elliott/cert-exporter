package metrics

import (
	"testing"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/client_golang/prometheus"
)

func TestInit_WithDefaultRegistry(t *testing.T) {
	// Create a new registry for testing to avoid conflicts with global state
	testRegistry := prometheus.NewRegistry()

	// Call Init with a custom registry
	Init(false, testRegistry)

	// Verify that metrics were registered by checking the gatherer
	metricFamilies, err := testRegistry.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	if len(metricFamilies) == 0 {
		t.Error("Expected metrics to be registered, but none were found")
	}

	// Note: Prometheus GaugeVecs without any labels set will not show up in Gather()
	// We just verify that ErrorTotal is present since it's a simple Counter
	foundErrorTotal := false
	for _, mf := range metricFamilies {
		if mf.GetName() == "cert_exporter_error_total" {
			foundErrorTotal = true
			break
		}
	}

	if !foundErrorTotal {
		t.Error("Expected cert_exporter_error_total to be registered")
	}
}

func TestInit_WithEmptyRegistry(t *testing.T) {
	// Save original registerer/gatherer
	originalRegisterer := prometheus.DefaultRegisterer
	originalGatherer := prometheus.DefaultGatherer
	defer func() {
		prometheus.DefaultRegisterer = originalRegisterer
		prometheus.DefaultGatherer = originalGatherer
	}()

	// Call Init with prometheusExporterMetricsDisabled=true and nil registry
	// This should create an empty registry and set it as the default
	Init(true, nil)

	// Verify that a new empty registry was created
	// The default registerer should now be an empty registry
	metricFamilies, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	// With a custom empty registry, we should still have our metrics registered
	// (the Init function creates an empty registry then registers our metrics to it)

	// Note: Prometheus GaugeVecs without any labels set will not show up in Gather()
	// We just verify that ErrorTotal is present since it's a simple Counter
	foundErrorTotal := false
	for _, mf := range metricFamilies {
		if mf.GetName() == "cert_exporter_error_total" {
			foundErrorTotal = true
			break
		}
	}

	if !foundErrorTotal {
		t.Error("Expected cert_exporter_error_total to be registered with custom empty registry")
	}
}

func TestMetricsNamespace(t *testing.T) {
	if namespace != "cert_exporter" {
		t.Errorf("Expected namespace to be 'cert_exporter', got '%s'", namespace)
	}
}

func TestMetricsDefinitions(t *testing.T) {
	// Test that all metric variables are defined and not nil
	metrics := map[string]interface{}{
		"BuildInfo":                       BuildInfo,
        "Discovered":                      Discovered,
    	"ErrorTotal":                      ErrorTotal,
		"CertExpirySeconds":               CertExpirySeconds,
		"CertNotAfterTimestamp":           CertNotAfterTimestamp,
		"CertNotBeforeTimestamp":          CertNotBeforeTimestamp,
		"KubeConfigExpirySeconds":         KubeConfigExpirySeconds,
		"KubeConfigNotAfterTimestamp":     KubeConfigNotAfterTimestamp,
		"KubeConfigNotBeforeTimestamp":    KubeConfigNotBeforeTimestamp,
		"SecretExpirySeconds":             SecretExpirySeconds,
		"SecretNotAfterTimestamp":         SecretNotAfterTimestamp,
		"SecretNotBeforeTimestamp":        SecretNotBeforeTimestamp,
		"CertRequestExpirySeconds":        CertRequestExpirySeconds,
		"CertRequestNotAfterTimestamp":    CertRequestNotAfterTimestamp,
		"CertRequestNotBeforeTimestamp":   CertRequestNotBeforeTimestamp,
		"AwsCertExpirySeconds":            AwsCertExpirySeconds,
		"ConfigMapExpirySeconds":          ConfigMapExpirySeconds,
		"ConfigMapNotAfterTimestamp":      ConfigMapNotAfterTimestamp,
		"ConfigMapNotBeforeTimestamp":     ConfigMapNotBeforeTimestamp,
		"WebhookExpirySeconds":            WebhookExpirySeconds,
		"WebhookNotAfterTimestamp":        WebhookNotAfterTimestamp,
		"WebhookNotBeforeTimestamp":       WebhookNotBeforeTimestamp,
  }

	for name, metric := range metrics {
		if metric == nil {
			t.Errorf("Metric %s is nil", name)
		}
	}
}

func TestCertExpirySecondsLabels(t *testing.T) {
	// Test that CertExpirySeconds has the correct labels
	labels := prometheus.Labels{
		"filename": "test.crt",
		"issuer":   "Test CA",
		"cn":       "test.example.com",
		"nodename": "node1",
	}

	// This should not panic
	gauge := CertExpirySeconds.With(labels)
	if gauge == nil {
		t.Error("Expected gauge to be created")
	}

	// Test setting a value
	gauge.Set(86400)
}

func TestCertNotAfterTimestampLabels(t *testing.T) {
	labels := prometheus.Labels{
		"filename": "test.crt",
		"issuer":   "Test CA",
		"cn":       "test.example.com",
		"nodename": "node1",
	}

	gauge := CertNotAfterTimestamp.With(labels)
	if gauge == nil {
		t.Error("Expected gauge to be created")
	}
	gauge.Set(1735689600)
}

func TestCertNotBeforeTimestampLabels(t *testing.T) {
	labels := prometheus.Labels{
		"filename": "test.crt",
		"issuer":   "Test CA",
		"cn":       "test.example.com",
		"nodename": "node1",
	}

	gauge := CertNotBeforeTimestamp.With(labels)
	if gauge == nil {
		t.Error("Expected gauge to be created")
	}
	gauge.Set(1704067200)
}

func TestKubeConfigExpirySecondsLabels(t *testing.T) {
	labels := prometheus.Labels{
		"filename": "kubeconfig.yaml",
		"type":     "client",
		"cn":       "kubernetes-admin",
		"issuer":   "kubernetes",
		"name":     "admin",
		"nodename": "node1",
	}

	gauge := KubeConfigExpirySeconds.With(labels)
	if gauge == nil {
		t.Error("Expected gauge to be created")
	}
	gauge.Set(2592000)
}

func TestKubeConfigNotAfterTimestampLabels(t *testing.T) {
	labels := prometheus.Labels{
		"filename": "kubeconfig.yaml",
		"type":     "client",
		"cn":       "kubernetes-admin",
		"issuer":   "kubernetes",
		"name":     "admin",
		"nodename": "node1",
	}

	gauge := KubeConfigNotAfterTimestamp.With(labels)
	if gauge == nil {
		t.Error("Expected gauge to be created")
	}
	gauge.Set(1735689600)
}

func TestKubeConfigNotBeforeTimestampLabels(t *testing.T) {
	labels := prometheus.Labels{
		"filename": "kubeconfig.yaml",
		"type":     "client",
		"cn":       "kubernetes-admin",
		"issuer":   "kubernetes",
		"name":     "admin",
		"nodename": "node1",
	}

	gauge := KubeConfigNotBeforeTimestamp.With(labels)
	if gauge == nil {
		t.Error("Expected gauge to be created")
	}
	gauge.Set(1704067200)
}

func TestSecretExpirySecondsLabels(t *testing.T) {
	labels := prometheus.Labels{
		"key_name":         "tls.crt",
		"issuer":           "Test CA",
		"cn":               "test.example.com",
		"secret_name":      "test-secret",
		"secret_namespace": "default",
	}

	gauge := SecretExpirySeconds.With(labels)
	if gauge == nil {
		t.Error("Expected gauge to be created")
	}
	gauge.Set(86400)
}

func TestSecretNotAfterTimestampLabels(t *testing.T) {
	labels := prometheus.Labels{
		"key_name":         "tls.crt",
		"issuer":           "Test CA",
		"cn":               "test.example.com",
		"secret_name":      "test-secret",
		"secret_namespace": "default",
	}

	gauge := SecretNotAfterTimestamp.With(labels)
	if gauge == nil {
		t.Error("Expected gauge to be created")
	}
	gauge.Set(1735689600)
}

func TestSecretNotBeforeTimestampLabels(t *testing.T) {
	labels := prometheus.Labels{
		"key_name":         "tls.crt",
		"issuer":           "Test CA",
		"cn":               "test.example.com",
		"secret_name":      "test-secret",
		"secret_namespace": "default",
	}

	gauge := SecretNotBeforeTimestamp.With(labels)
	if gauge == nil {
		t.Error("Expected gauge to be created")
	}
	gauge.Set(1704067200)
}

func TestCertRequestExpirySecondsLabels(t *testing.T) {
	labels := prometheus.Labels{
		"issuer":                "letsencrypt",
		"cn":                    "test.example.com",
		"cert_request":          "test-cert-request",
		"certrequest_namespace": "cert-manager",
	}

	gauge := CertRequestExpirySeconds.With(labels)
	if gauge == nil {
		t.Error("Expected gauge to be created")
	}
	gauge.Set(7776000)
}

func TestCertRequestNotAfterTimestampLabels(t *testing.T) {
	labels := prometheus.Labels{
		"issuer":                "letsencrypt",
		"cn":                    "test.example.com",
		"cert_request":          "test-cert-request",
		"certrequest_namespace": "cert-manager",
	}

	gauge := CertRequestNotAfterTimestamp.With(labels)
	if gauge == nil {
		t.Error("Expected gauge to be created")
	}
	gauge.Set(1735689600)
}

func TestCertRequestNotBeforeTimestampLabels(t *testing.T) {
	labels := prometheus.Labels{
		"issuer":                "letsencrypt",
		"cn":                    "test.example.com",
		"cert_request":          "test-cert-request",
		"certrequest_namespace": "cert-manager",
	}

	gauge := CertRequestNotBeforeTimestamp.With(labels)
	if gauge == nil {
		t.Error("Expected gauge to be created")
	}
	gauge.Set(1704067200)
}

func TestAwsCertExpirySecondsLabels(t *testing.T) {
	labels := prometheus.Labels{
		"secretName": "aws-secret",
		"key":        "certificate.pem",
		"file":       "/tmp/cert.pem",
		"issuer":     "AWS CA",
		"cn":         "aws.example.com",
	}

	gauge := AwsCertExpirySeconds.With(labels)
	if gauge == nil {
		t.Error("Expected gauge to be created")
	}
	gauge.Set(86400)
}

func TestConfigMapExpirySecondsLabels(t *testing.T) {
	labels := prometheus.Labels{
		"key_name":            "ca.crt",
		"issuer":              "Test CA",
		"cn":                  "test.example.com",
		"configmap_name":      "test-configmap",
		"configmap_namespace": "default",
	}

	gauge := ConfigMapExpirySeconds.With(labels)
	if gauge == nil {
		t.Error("Expected gauge to be created")
	}
	gauge.Set(86400)
}

func TestConfigMapNotAfterTimestampLabels(t *testing.T) {
	labels := prometheus.Labels{
		"key_name":            "ca.crt",
		"issuer":              "Test CA",
		"cn":                  "test.example.com",
		"configmap_name":      "test-configmap",
		"configmap_namespace": "default",
	}

	gauge := ConfigMapNotAfterTimestamp.With(labels)
	if gauge == nil {
		t.Error("Expected gauge to be created")
	}
	gauge.Set(1735689600)
}

func TestConfigMapNotBeforeTimestampLabels(t *testing.T) {
	labels := prometheus.Labels{
		"key_name":            "ca.crt",
		"issuer":              "Test CA",
		"cn":                  "test.example.com",
		"configmap_name":      "test-configmap",
		"configmap_namespace": "default",
	}

	gauge := ConfigMapNotBeforeTimestamp.With(labels)
	if gauge == nil {
		t.Error("Expected gauge to be created")
	}
	gauge.Set(1704067200)
}

func TestWebhookExpirySecondsLabels(t *testing.T) {
	labels := prometheus.Labels{
		"type_name":                     "validating",
		"issuer":                        "webhook-ca",
		"cn":                            "webhook.example.com",
		"webhook_name":                  "test-webhook",
		"admission_review_version_name": "v1",
	}

	gauge := WebhookExpirySeconds.With(labels)
	if gauge == nil {
		t.Error("Expected gauge to be created")
	}
	gauge.Set(86400)
}

func TestWebhookNotAfterTimestampLabels(t *testing.T) {
	labels := prometheus.Labels{
		"type_name":                     "validating",
		"issuer":                        "webhook-ca",
		"cn":                            "webhook.example.com",
		"webhook_name":                  "test-webhook",
		"admission_review_version_name": "v1",
	}

	gauge := WebhookNotAfterTimestamp.With(labels)
	if gauge == nil {
		t.Error("Expected gauge to be created")
	}
	gauge.Set(1735689600)
}

func TestWebhookNotBeforeTimestampLabels(t *testing.T) {
	labels := prometheus.Labels{
		"type_name":                     "validating",
		"issuer":                        "webhook-ca",
		"cn":                            "webhook.example.com",
		"webhook_name":                  "test-webhook",
		"admission_review_version_name": "v1",
	}

	gauge := WebhookNotBeforeTimestamp.With(labels)
	if gauge == nil {
		t.Error("Expected gauge to be created")
	}
	gauge.Set(1704067200)
}

func TestBuildInfo(t *testing.T) {
	collector := BuildInfo
	
	// Collect build_info metric from the channel
	ch := make(chan prometheus.Metric, 1)
	collector.Collect(ch)
	m := <-ch

	// Write the metric data into a DTO struct
	pb := &dto.Metric{}
	m.Write(pb)

	// Format and Log the labels to the test console
	actualLabels := make(map[string]string)
	t.Log("--- Labels Found in BuildInfo Collector ---")
	for _, lp := range pb.GetLabel() {
		t.Logf("Label: %-10s | Value: %s", lp.GetName(), lp.GetValue())
		actualLabels[lp.GetName()] = lp.GetValue()
	}
	t.Log("------------------------------------")
	
	// Define expected labels (common build_info labels)
	expectedLabels := []string{
		"version",
		"revision",
		"branch",
		"goversion",
		"goarch",
		"goos",
		"tags",
	}
	// Note: Compile ldflags in goreleaser populate labels, some will be empty
	// but we can verify each expected label exists
	for _, expectedLabel := range expectedLabels {
		if _, exists := actualLabels[expectedLabel]; !exists {
			t.Errorf("Expected label %q not found in build_info metric", expectedLabel)
		}
	}
}


func TestErrorTotalCounter(t *testing.T) {
	// Test that ErrorTotal counter can be incremented
	// Note: We can't easily verify the actual value due to global state,
	// but we can verify it doesn't panic
	ErrorTotal.Inc()
}

func TestDiscoveredGauge(t *testing.T) {
	// Test that Discovered gauge can be set and updated
	// Note: We can't easily verify the actual value due to global state,
	// but we can verify it doesn't panic
	Discovered.Set(10)
	Discovered.Inc()
	Discovered.Dec()
	Discovered.Add(5)
	Discovered.Sub(3)
}
