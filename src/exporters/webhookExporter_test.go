package exporters

import (
	"testing"

	"github.com/joe-elliott/cert-exporter/internal/testutil"
	"github.com/joe-elliott/cert-exporter/src/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

func TestWebhookExporter_ExportMetrics(t *testing.T) {
	testRegistry := prometheus.NewRegistry()
	metrics.Init(true, testRegistry)

	// Generate test certificate
	cert := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName:   "test-webhook",
		Organization: "test-org",
		Country:      "US",
		Province:     "CA",
		Days:         30,
		IsCA:         false,
	})

	exporter := &WebhookExporter{}
	exporter.ResetMetrics()

	// Export metrics
	err := exporter.ExportMetrics(cert.CertPEM, "MutatingWebhook", "test-webhook", "v1")
	if err != nil {
		t.Fatalf("Failed to export metrics: %v", err)
	}

	// Verify metrics were created
	mfs, err := testRegistry.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	foundExpiry := false
	foundNotAfter := false
	foundNotBefore := false

	for _, mf := range mfs {
		switch mf.GetName() {
		case "cert_exporter_webhook_expires_in_seconds":
			for _, metric := range mf.GetMetric() {
				labels := getLabelMap(metric)
				if labels["cn"] == "test-webhook" && labels["webhook_name"] == "test-webhook" && labels["type_name"] == "MutatingWebhook" {
					foundExpiry = true
					value := metric.GetGauge().GetValue()
					if value <= 0 {
						t.Errorf("Expected positive expiry seconds, got %v", value)
					}
				}
			}
		case "cert_exporter_webhook_not_after_timestamp":
			for _, metric := range mf.GetMetric() {
				labels := getLabelMap(metric)
				if labels["cn"] == "test-webhook" {
					foundNotAfter = true
				}
			}
		case "cert_exporter_webhook_not_before_timestamp":
			for _, metric := range mf.GetMetric() {
				labels := getLabelMap(metric)
				if labels["cn"] == "test-webhook" {
					foundNotBefore = true
				}
			}
		}
	}

	if !foundExpiry {
		t.Error("Expected to find webhook_expires_in_seconds metric")
	}
	if !foundNotAfter {
		t.Error("Expected to find webhook_not_after_timestamp metric")
	}
	if !foundNotBefore {
		t.Error("Expected to find webhook_not_before_timestamp metric")
	}
}

func TestWebhookExporter_ExportMetrics_ValidatingWebhook(t *testing.T) {
	testRegistry := prometheus.NewRegistry()
	metrics.Init(true, testRegistry)

	// Generate test certificate
	cert := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName:   "validating-webhook",
		Organization: "test-org",
		Country:      "US",
		Province:     "CA",
		Days:         60,
		IsCA:         false,
	})

	exporter := &WebhookExporter{}
	exporter.ResetMetrics()

	// Export metrics for ValidatingWebhook
	err := exporter.ExportMetrics(cert.CertPEM, "ValidatingWebhook", "test-validating-webhook", "v1beta1")
	if err != nil {
		t.Fatalf("Failed to export metrics: %v", err)
	}

	// Verify metrics
	mfs, err := testRegistry.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	found := false
	for _, mf := range mfs {
		if mf.GetName() == "cert_exporter_webhook_expires_in_seconds" {
			for _, metric := range mf.GetMetric() {
				labels := getLabelMap(metric)
				if labels["webhook_name"] == "test-validating-webhook" && labels["type_name"] == "ValidatingWebhook" {
					found = true
					if labels["admission_review_version_name"] != "v1beta1" {
						t.Errorf("Expected admission_review_version_name 'v1beta1', got '%s'", labels["admission_review_version_name"])
					}
				}
			}
		}
	}

	if !found {
		t.Error("Expected to find metric for ValidatingWebhook")
	}
}

func TestWebhookExporter_ExportMetrics_Bundle(t *testing.T) {
	testRegistry := prometheus.NewRegistry()
	metrics.Init(true, testRegistry)

	// Generate CA and signed cert
	caCert := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName:   "webhook-ca",
		Organization: "test-org",
		Country:      "US",
		Province:     "CA",
		Days:         365,
		IsCA:         true,
	})

	signedCert := testutil.GenerateSignedCertificate(t, testutil.CertConfig{
		CommonName:   "webhook-signed",
		Organization: "test-org",
		Country:      "US",
		Province:     "CA",
		Days:         180,
		IsCA:         false,
	}, caCert)

	// Create bundle
	bundle := testutil.CreateCertBundle(signedCert, caCert)

	exporter := &WebhookExporter{}
	exporter.ResetMetrics()

	// Export bundle metrics
	err := exporter.ExportMetrics(bundle, "MutatingWebhook", "bundle-webhook", "v1")
	if err != nil {
		t.Fatalf("Failed to export bundle metrics: %v", err)
	}

	// Verify metrics for both certs in bundle
	mfs, err := testRegistry.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	foundCA := false
	foundSigned := false

	for _, mf := range mfs {
		if mf.GetName() == "cert_exporter_webhook_expires_in_seconds" {
			for _, metric := range mf.GetMetric() {
				labels := getLabelMap(metric)
				if labels["webhook_name"] == "bundle-webhook" {
					if labels["cn"] == "webhook-ca" {
						foundCA = true
					}
					if labels["cn"] == "webhook-signed" {
						foundSigned = true
					}
				}
			}
		}
	}

	if !foundCA {
		t.Error("Expected to find metric for webhook-ca in bundle")
	}
	if !foundSigned {
		t.Error("Expected to find metric for webhook-signed in bundle")
	}
}

func TestWebhookExporter_ExportMetrics_MultipleWebhooks(t *testing.T) {
	testRegistry := prometheus.NewRegistry()
	metrics.Init(true, testRegistry)

	// Generate test certificates
	cert1 := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName: "webhook1", Organization: "test-org", Country: "US", Province: "CA", Days: 30,
	})

	cert2 := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName: "webhook2", Organization: "test-org", Country: "US", Province: "CA", Days: 60,
	})

	exporter := &WebhookExporter{}
	exporter.ResetMetrics()

	// Export metrics for multiple webhooks
	err := exporter.ExportMetrics(cert1.CertPEM, "MutatingWebhook", "webhook-1", "v1")
	if err != nil {
		t.Fatalf("Failed to export webhook1 metrics: %v", err)
	}

	err = exporter.ExportMetrics(cert2.CertPEM, "ValidatingWebhook", "webhook-2", "v1")
	if err != nil {
		t.Fatalf("Failed to export webhook2 metrics: %v", err)
	}

	// Verify metrics for both webhooks
	mfs, err := testRegistry.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	foundWebhook1 := false
	foundWebhook2 := false

	for _, mf := range mfs {
		if mf.GetName() == "cert_exporter_webhook_expires_in_seconds" {
			for _, metric := range mf.GetMetric() {
				labels := getLabelMap(metric)
				if labels["webhook_name"] == "webhook-1" && labels["type_name"] == "MutatingWebhook" {
					foundWebhook1 = true
				}
				if labels["webhook_name"] == "webhook-2" && labels["type_name"] == "ValidatingWebhook" {
					foundWebhook2 = true
				}
			}
		}
	}

	if !foundWebhook1 {
		t.Error("Expected to find metric for webhook-1")
	}
	if !foundWebhook2 {
		t.Error("Expected to find metric for webhook-2")
	}
}

func TestWebhookExporter_ExportMetrics_InvalidCert(t *testing.T) {
	testRegistry := prometheus.NewRegistry()
	metrics.Init(true, testRegistry)

	exporter := &WebhookExporter{}
	exporter.ResetMetrics()

	// Try to export invalid certificate data
	err := exporter.ExportMetrics([]byte("not a valid certificate"), "MutatingWebhook", "invalid-webhook", "v1")
	if err == nil {
		t.Error("Expected error when exporting invalid certificate data")
	}
}

func TestWebhookExporter_ResetMetrics(t *testing.T) {
	testRegistry := prometheus.NewRegistry()
	metrics.Init(true, testRegistry)

	// Generate and export test certificate
	cert := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName: "reset-test", Organization: "test-org", Country: "US", Province: "CA", Days: 30,
	})

	exporter := &WebhookExporter{}
	exporter.ResetMetrics()

	err := exporter.ExportMetrics(cert.CertPEM, "MutatingWebhook", "reset-webhook", "v1")
	if err != nil {
		t.Fatalf("Failed to export metrics: %v", err)
	}

	// Verify metric exists
	mfs, err := testRegistry.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	foundBefore := false
	for _, mf := range mfs {
		if mf.GetName() == "cert_exporter_webhook_expires_in_seconds" {
			if len(mf.GetMetric()) > 0 {
				foundBefore = true
			}
		}
	}

	if !foundBefore {
		t.Error("Expected to find metrics before reset")
	}

	// Reset metrics
	exporter.ResetMetrics()

	// Verify metrics are reset
	mfs, err = testRegistry.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	for _, mf := range mfs {
		if mf.GetName() == "cert_exporter_webhook_expires_in_seconds" {
			if len(mf.GetMetric()) > 0 {
				t.Error("Expected metrics to be reset, but found metrics")
			}
		}
	}
}

func TestWebhookExporter_LabelValues(t *testing.T) {
	testRegistry := prometheus.NewRegistry()
	metrics.Init(true, testRegistry)

	// Generate test certificate
	cert := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName:   "label-test-webhook",
		Organization: "webhook-org",
		Country:      "US",
		Province:     "CA",
		Days:         30,
		IsCA:         false,
	})

	exporter := &WebhookExporter{}
	exporter.ResetMetrics()

	typeName := "MutatingWebhook"
	webhookName := "test-webhook-labels"
	admissionReviewVersion := "v1beta1"

	err := exporter.ExportMetrics(cert.CertPEM, typeName, webhookName, admissionReviewVersion)
	if err != nil {
		t.Fatalf("Failed to export metrics: %v", err)
	}

	// Verify label values
	mfs, err := testRegistry.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	for _, mf := range mfs {
		if mf.GetName() == "cert_exporter_webhook_expires_in_seconds" {
			for _, metric := range mf.GetMetric() {
				labels := getLabelMap(metric)
				if labels["webhook_name"] == webhookName {
					if labels["type_name"] != typeName {
						t.Errorf("Expected type_name '%s', got '%s'", typeName, labels["type_name"])
					}
					if labels["admission_review_version_name"] != admissionReviewVersion {
						t.Errorf("Expected admission_review_version_name '%s', got '%s'", admissionReviewVersion, labels["admission_review_version_name"])
					}
					if labels["cn"] != "label-test-webhook" {
						t.Errorf("Expected cn 'label-test-webhook', got '%s'", labels["cn"])
					}
				}
			}
		}
	}
}
