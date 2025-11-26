package exporters

import (
	"strings"
	"testing"

	"github.com/joe-elliott/cert-exporter/internal/testutil"
	"github.com/joe-elliott/cert-exporter/src/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

func TestCertRequestExporter_ExportMetrics(t *testing.T) {
	metrics.Init(true)

	// Generate test certificate
	cert := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName:   "test-certrequest",
		Organization: "test-org",
		Country:      "US",
		Province:     "CA",
		Days:         30,
		IsCA:         false,
	})

	exporter := &CertRequestExporter{}
	exporter.ResetMetrics()

	// Export metrics
	err := exporter.ExportMetrics(cert.CertPEM, "test-certrequest", "test-namespace")
	if err != nil {
		t.Fatalf("Failed to export metrics: %v", err)
	}

	// Verify metrics were created
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	foundExpiry := false
	foundNotAfter := false
	foundNotBefore := false

	for _, mf := range mfs {
		switch mf.GetName() {
		case "cert_exporter_certrequest_expires_in_seconds":
			for _, metric := range mf.GetMetric() {
				labels := getLabelMap(metric)
				if labels["cn"] == "test-certrequest" && labels["cert_request"] == "test-certrequest" && labels["certrequest_namespace"] == "test-namespace" {
					foundExpiry = true
					value := metric.GetGauge().GetValue()
					if value <= 0 {
						t.Errorf("Expected positive expiry seconds, got %v", value)
					}
				}
			}
		case "cert_exporter_certrequest_not_after_timestamp":
			for _, metric := range mf.GetMetric() {
				labels := getLabelMap(metric)
				if labels["cn"] == "test-certrequest" {
					foundNotAfter = true
				}
			}
		case "cert_exporter_certrequest_not_before_timestamp":
			for _, metric := range mf.GetMetric() {
				labels := getLabelMap(metric)
				if labels["cn"] == "test-certrequest" {
					foundNotBefore = true
				}
			}
		}
	}

	if !foundExpiry {
		t.Error("Expected to find certrequest_expires_in_seconds metric")
	}
	if !foundNotAfter {
		t.Error("Expected to find certrequest_not_after_timestamp metric")
	}
	if !foundNotBefore {
		t.Error("Expected to find certrequest_not_before_timestamp metric")
	}
}

func TestCertRequestExporter_ExportMetrics_Bundle(t *testing.T) {
	metrics.Init(true)

	// Generate CA and signed cert
	caCert := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName:   "certrequest-ca",
		Organization: "test-org",
		Country:      "US",
		Province:     "CA",
		Days:         365,
		IsCA:         true,
	})

	signedCert := testutil.GenerateSignedCertificate(t, testutil.CertConfig{
		CommonName:   "certrequest-signed",
		Organization: "test-org",
		Country:      "US",
		Province:     "CA",
		Days:         180,
		IsCA:         false,
	}, caCert)

	// Create bundle
	bundle := testutil.CreateCertBundle(signedCert, caCert)

	exporter := &CertRequestExporter{}
	exporter.ResetMetrics()

	// Export bundle metrics
	err := exporter.ExportMetrics(bundle, "bundle-certrequest", "test-namespace")
	if err != nil {
		t.Fatalf("Failed to export bundle metrics: %v", err)
	}

	// Verify metrics for both certs in bundle
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	foundCA := false
	foundSigned := false

	for _, mf := range mfs {
		if mf.GetName() == "cert_exporter_certrequest_expires_in_seconds" {
			for _, metric := range mf.GetMetric() {
				labels := getLabelMap(metric)
				if labels["cert_request"] == "bundle-certrequest" {
					if labels["cn"] == "certrequest-ca" {
						foundCA = true
					}
					if labels["cn"] == "certrequest-signed" {
						foundSigned = true
					}
				}
			}
		}
	}

	if !foundCA {
		t.Error("Expected to find metric for certrequest-ca in bundle")
	}
	if !foundSigned {
		t.Error("Expected to find metric for certrequest-signed in bundle")
	}
}

func TestCertRequestExporter_ExportMetrics_MultipleNamespaces(t *testing.T) {
	metrics.Init(true)

	// Generate test certificates
	cert1 := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName: "cr-ns1", Organization: "test-org", Country: "US", Province: "CA", Days: 30,
	})

	cert2 := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName: "cr-ns2", Organization: "test-org", Country: "US", Province: "CA", Days: 60,
	})

	exporter := &CertRequestExporter{}
	exporter.ResetMetrics()

	// Export metrics for different namespaces
	err := exporter.ExportMetrics(cert1.CertPEM, "certrequest-1", "namespace-1")
	if err != nil {
		t.Fatalf("Failed to export cert1 metrics: %v", err)
	}

	err = exporter.ExportMetrics(cert2.CertPEM, "certrequest-2", "namespace-2")
	if err != nil {
		t.Fatalf("Failed to export cert2 metrics: %v", err)
	}

	// Verify metrics for both namespaces
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	foundNs1 := false
	foundNs2 := false

	for _, mf := range mfs {
		if mf.GetName() == "cert_exporter_certrequest_expires_in_seconds" {
			for _, metric := range mf.GetMetric() {
				labels := getLabelMap(metric)
				if labels["cert_request"] == "certrequest-1" && labels["certrequest_namespace"] == "namespace-1" {
					foundNs1 = true
				}
				if labels["cert_request"] == "certrequest-2" && labels["certrequest_namespace"] == "namespace-2" {
					foundNs2 = true
				}
			}
		}
	}

	if !foundNs1 {
		t.Error("Expected to find metric for namespace-1")
	}
	if !foundNs2 {
		t.Error("Expected to find metric for namespace-2")
	}
}

func TestCertRequestExporter_ExportMetrics_InvalidCert(t *testing.T) {
	metrics.Init(true)

	exporter := &CertRequestExporter{}
	exporter.ResetMetrics()

	// Try to export invalid certificate data
	err := exporter.ExportMetrics([]byte("not a valid certificate"), "invalid-certrequest", "test-namespace")
	if err == nil {
		t.Error("Expected error when exporting invalid certificate data")
	}
}

func TestCertRequestExporter_ResetMetrics(t *testing.T) {
	metrics.Init(true)

	// Generate and export test certificate
	cert := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName: "reset-test", Organization: "test-org", Country: "US", Province: "CA", Days: 30,
	})

	exporter := &CertRequestExporter{}
	exporter.ResetMetrics()

	err := exporter.ExportMetrics(cert.CertPEM, "reset-certrequest", "test-namespace")
	if err != nil {
		t.Fatalf("Failed to export metrics: %v", err)
	}

	// Verify metric exists
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	foundBefore := false
	for _, mf := range mfs {
		if mf.GetName() == "cert_exporter_certrequest_expires_in_seconds" {
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
	mfs, err = prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	for _, mf := range mfs {
		if mf.GetName() == "cert_exporter_certrequest_expires_in_seconds" {
			if len(mf.GetMetric()) > 0 {
				t.Error("Expected metrics to be reset, but found metrics")
			}
		}
	}
}

func TestCertRequestExporter_LabelValues(t *testing.T) {
	metrics.Init(true)

	// Generate test certificate with specific issuer
	caCert := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName:   "test-issuer",
		Organization: "issuer-org",
		Country:      "US",
		Province:     "CA",
		Days:         365,
		IsCA:         true,
	})

	signedCert := testutil.GenerateSignedCertificate(t, testutil.CertConfig{
		CommonName:   "label-test",
		Organization: "test-org",
		Country:      "US",
		Province:     "CA",
		Days:         30,
		IsCA:         false,
	}, caCert)

	exporter := &CertRequestExporter{}
	exporter.ResetMetrics()

	certRequestName := "test-certrequest"
	namespace := "test-ns"

	err := exporter.ExportMetrics(signedCert.CertPEM, certRequestName, namespace)
	if err != nil {
		t.Fatalf("Failed to export metrics: %v", err)
	}

	// Verify label values
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	for _, mf := range mfs {
		if mf.GetName() == "cert_exporter_certrequest_expires_in_seconds" {
			for _, metric := range mf.GetMetric() {
				labels := getLabelMap(metric)
				if labels["cert_request"] == certRequestName {
					if labels["certrequest_namespace"] != namespace {
						t.Errorf("Expected certrequest_namespace '%s', got '%s'", namespace, labels["certrequest_namespace"])
					}
					if labels["cn"] != "label-test" {
						t.Errorf("Expected cn 'label-test', got '%s'", labels["cn"])
					}
					if labels["issuer"] == "" {
						t.Error("Expected non-empty issuer")
					}
					// Check that issuer contains the expected CN
					if !strings.Contains(labels["issuer"], "test-issuer") {
						t.Errorf("Expected issuer to contain 'test-issuer', got '%s'", labels["issuer"])
					}
				}
			}
		}
	}
}
