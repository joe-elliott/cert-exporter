package exporters

import (
	"testing"

	"github.com/joe-elliott/cert-exporter/internal/testutil"
	"github.com/joe-elliott/cert-exporter/src/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

func TestConfigMapExporter_ExportMetrics(t *testing.T) {
	testRegistry := prometheus.NewRegistry()
	metrics.Init(true, testRegistry)

	// Generate test certificate
	cert := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName:   "test-configmap",
		Organization: "test-org",
		Country:      "US",
		Province:     "CA",
		Days:         30,
		IsCA:         false,
	})

	exporter := &ConfigMapExporter{}
	exporter.ResetMetrics()

	// Export metrics
	err := exporter.ExportMetrics(cert.CertPEM, "ca.crt", "test-configmap", "test-namespace")
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
		case "cert_exporter_configmap_expires_in_seconds":
			for _, metric := range mf.GetMetric() {
				labels := getLabelMap(metric)
				if labels["cn"] == "test-configmap" && labels["configmap_name"] == "test-configmap" && labels["configmap_namespace"] == "test-namespace" {
					foundExpiry = true
					value := metric.GetGauge().GetValue()
					if value <= 0 {
						t.Errorf("Expected positive expiry seconds, got %v", value)
					}
				}
			}
		case "cert_exporter_configmap_not_after_timestamp":
			for _, metric := range mf.GetMetric() {
				labels := getLabelMap(metric)
				if labels["cn"] == "test-configmap" {
					foundNotAfter = true
				}
			}
		case "cert_exporter_configmap_not_before_timestamp":
			for _, metric := range mf.GetMetric() {
				labels := getLabelMap(metric)
				if labels["cn"] == "test-configmap" {
					foundNotBefore = true
				}
			}
		}
	}

	if !foundExpiry {
		t.Error("Expected to find configmap_expires_in_seconds metric")
	}
	if !foundNotAfter {
		t.Error("Expected to find configmap_not_after_timestamp metric")
	}
	if !foundNotBefore {
		t.Error("Expected to find configmap_not_before_timestamp metric")
	}
}

func TestConfigMapExporter_ExportMetrics_Bundle(t *testing.T) {
	testRegistry := prometheus.NewRegistry()
	metrics.Init(true, testRegistry)

	// Generate CA and intermediate cert
	caCert := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName:   "configmap-ca",
		Organization: "test-org",
		Country:      "US",
		Province:     "CA",
		Days:         365,
		IsCA:         true,
	})

	intermediateCert := testutil.GenerateSignedCertificate(t, testutil.CertConfig{
		CommonName:   "configmap-intermediate",
		Organization: "test-org",
		Country:      "US",
		Province:     "CA",
		Days:         180,
		IsCA:         false,
	}, caCert)

	// Create bundle
	bundle := testutil.CreateCertBundle(intermediateCert, caCert)

	exporter := &ConfigMapExporter{}
	exporter.ResetMetrics()

	// Export bundle metrics
	err := exporter.ExportMetrics(bundle, "ca-bundle.crt", "bundle-configmap", "test-namespace")
	if err != nil {
		t.Fatalf("Failed to export bundle metrics: %v", err)
	}

	// Verify metrics for both certs in bundle
	mfs, err := testRegistry.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	foundCA := false
	foundIntermediate := false

	for _, mf := range mfs {
		if mf.GetName() == "cert_exporter_configmap_expires_in_seconds" {
			for _, metric := range mf.GetMetric() {
				labels := getLabelMap(metric)
				if labels["configmap_name"] == "bundle-configmap" {
					if labels["cn"] == "configmap-ca" {
						foundCA = true
					}
					if labels["cn"] == "configmap-intermediate" {
						foundIntermediate = true
					}
				}
			}
		}
	}

	if !foundCA {
		t.Error("Expected to find metric for configmap-ca in bundle")
	}
	if !foundIntermediate {
		t.Error("Expected to find metric for configmap-intermediate in bundle")
	}
}

func TestConfigMapExporter_ExportMetrics_MultipleKeys(t *testing.T) {
	testRegistry := prometheus.NewRegistry()
	metrics.Init(true, testRegistry)

	// Generate multiple certificates
	cert1 := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName: "cert1", Organization: "test-org", Country: "US", Province: "CA", Days: 30,
	})

	cert2 := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName: "cert2", Organization: "test-org", Country: "US", Province: "CA", Days: 60,
	})

	exporter := &ConfigMapExporter{}
	exporter.ResetMetrics()

	// Export metrics for multiple keys in same configmap
	err := exporter.ExportMetrics(cert1.CertPEM, "cert1.crt", "multi-key-configmap", "test-namespace")
	if err != nil {
		t.Fatalf("Failed to export cert1 metrics: %v", err)
	}

	err = exporter.ExportMetrics(cert2.CertPEM, "cert2.crt", "multi-key-configmap", "test-namespace")
	if err != nil {
		t.Fatalf("Failed to export cert2 metrics: %v", err)
	}

	// Verify metrics for both keys
	mfs, err := testRegistry.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	foundCert1 := false
	foundCert2 := false

	for _, mf := range mfs {
		if mf.GetName() == "cert_exporter_configmap_expires_in_seconds" {
			for _, metric := range mf.GetMetric() {
				labels := getLabelMap(metric)
				if labels["configmap_name"] == "multi-key-configmap" {
					if labels["key_name"] == "cert1.crt" && labels["cn"] == "cert1" {
						foundCert1 = true
					}
					if labels["key_name"] == "cert2.crt" && labels["cn"] == "cert2" {
						foundCert2 = true
					}
				}
			}
		}
	}

	if !foundCert1 {
		t.Error("Expected to find metric for cert1.crt")
	}
	if !foundCert2 {
		t.Error("Expected to find metric for cert2.crt")
	}
}

func TestConfigMapExporter_ExportMetrics_InvalidCert(t *testing.T) {
	testRegistry := prometheus.NewRegistry()
	metrics.Init(true, testRegistry)

	exporter := &ConfigMapExporter{}
	exporter.ResetMetrics()

	// Try to export invalid certificate data
	err := exporter.ExportMetrics([]byte("not a valid certificate"), "invalid.crt", "invalid-configmap", "test-namespace")
	if err == nil {
		t.Error("Expected error when exporting invalid certificate data")
	}
}

func TestConfigMapExporter_ResetMetrics(t *testing.T) {
	testRegistry := prometheus.NewRegistry()
	metrics.Init(true, testRegistry)

	// Generate and export test certificate
	cert := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName: "reset-test", Organization: "test-org", Country: "US", Province: "CA", Days: 30,
	})

	exporter := &ConfigMapExporter{}
	exporter.ResetMetrics()

	err := exporter.ExportMetrics(cert.CertPEM, "ca.crt", "reset-configmap", "test-namespace")
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
		if mf.GetName() == "cert_exporter_configmap_expires_in_seconds" {
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
		if mf.GetName() == "cert_exporter_configmap_expires_in_seconds" {
			if len(mf.GetMetric()) > 0 {
				t.Error("Expected metrics to be reset, but found metrics")
			}
		}
	}
}

func TestConfigMapExporter_LabelValues(t *testing.T) {
	testRegistry := prometheus.NewRegistry()
	metrics.Init(true, testRegistry)

	// Generate test certificate with specific fields
	cert := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName:   "label-test",
		Organization: "label-org",
		Country:      "US",
		Province:     "CA",
		Days:         30,
		IsCA:         false,
	})

	exporter := &ConfigMapExporter{}
	exporter.ResetMetrics()

	keyName := "test-key.crt"
	configMapName := "test-labels-configmap"
	configMapNamespace := "test-labels-ns"

	err := exporter.ExportMetrics(cert.CertPEM, keyName, configMapName, configMapNamespace)
	if err != nil {
		t.Fatalf("Failed to export metrics: %v", err)
	}

	// Verify label values
	mfs, err := testRegistry.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	for _, mf := range mfs {
		if mf.GetName() == "cert_exporter_configmap_expires_in_seconds" {
			for _, metric := range mf.GetMetric() {
				labels := getLabelMap(metric)
				if labels["configmap_name"] == configMapName {
					if labels["key_name"] != keyName {
						t.Errorf("Expected key_name '%s', got '%s'", keyName, labels["key_name"])
					}
					if labels["configmap_namespace"] != configMapNamespace {
						t.Errorf("Expected configmap_namespace '%s', got '%s'", configMapNamespace, labels["configmap_namespace"])
					}
					if labels["cn"] != "label-test" {
						t.Errorf("Expected cn 'label-test', got '%s'", labels["cn"])
					}
				}
			}
		}
	}
}
