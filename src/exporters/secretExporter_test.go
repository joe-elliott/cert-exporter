package exporters

import (
	"testing"

	"github.com/joe-elliott/cert-exporter/internal/testutil"
	"github.com/joe-elliott/cert-exporter/src/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

func TestSecretExporter_ExportMetrics(t *testing.T) {
	metrics.Init(true)

	// Generate test certificate
	cert := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName:   "test-secret",
		Organization: "test-org",
		Country:      "US",
		Province:     "CA",
		Days:         30,
		IsCA:         false,
	})

	exporter := &SecretExporter{}
	exporter.ResetMetrics()

	// Export metrics
	err := exporter.ExportMetrics(cert.CertPEM, "tls.crt", "test-secret", "test-namespace", "")
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
		case "cert_exporter_secret_expires_in_seconds":
			for _, metric := range mf.GetMetric() {
				labels := getLabelMap(metric)
				if labels["cn"] == "test-secret" && labels["secret_name"] == "test-secret" && labels["secret_namespace"] == "test-namespace" {
					foundExpiry = true
					value := metric.GetGauge().GetValue()
					if value <= 0 {
						t.Errorf("Expected positive expiry seconds, got %v", value)
					}
				}
			}
		case "cert_exporter_secret_not_after_timestamp":
			for _, metric := range mf.GetMetric() {
				labels := getLabelMap(metric)
				if labels["cn"] == "test-secret" {
					foundNotAfter = true
				}
			}
		case "cert_exporter_secret_not_before_timestamp":
			for _, metric := range mf.GetMetric() {
				labels := getLabelMap(metric)
				if labels["cn"] == "test-secret" {
					foundNotBefore = true
				}
			}
		}
	}

	if !foundExpiry {
		t.Error("Expected to find secret_expires_in_seconds metric")
	}
	if !foundNotAfter {
		t.Error("Expected to find secret_not_after_timestamp metric")
	}
	if !foundNotBefore {
		t.Error("Expected to find secret_not_before_timestamp metric")
	}
}

func TestSecretExporter_ExportMetrics_Bundle(t *testing.T) {
	metrics.Init(true)

	// Generate CA and intermediate cert
	caCert := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName:   "ca-cert",
		Organization: "test-org",
		Country:      "US",
		Province:     "CA",
		Days:         365,
		IsCA:         true,
	})

	intermediateCert := testutil.GenerateSignedCertificate(t, testutil.CertConfig{
		CommonName:   "intermediate-cert",
		Organization: "test-org",
		Country:      "US",
		Province:     "CA",
		Days:         180,
		IsCA:         false,
	}, caCert)

	// Create bundle
	bundle := testutil.CreateCertBundle(intermediateCert, caCert)

	exporter := &SecretExporter{}
	exporter.ResetMetrics()

	// Export bundle metrics
	err := exporter.ExportMetrics(bundle, "ca-bundle.crt", "bundle-secret", "test-namespace", "")
	if err != nil {
		t.Fatalf("Failed to export bundle metrics: %v", err)
	}

	// Verify metrics for both certs in bundle
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	foundCA := false
	foundIntermediate := false

	for _, mf := range mfs {
		if mf.GetName() == "cert_exporter_secret_expires_in_seconds" {
			for _, metric := range mf.GetMetric() {
				labels := getLabelMap(metric)
				if labels["secret_name"] == "bundle-secret" {
					if labels["cn"] == "ca-cert" {
						foundCA = true
					}
					if labels["cn"] == "intermediate-cert" {
						foundIntermediate = true
					}
				}
			}
		}
	}

	if !foundCA {
		t.Error("Expected to find metric for ca-cert in bundle")
	}
	if !foundIntermediate {
		t.Error("Expected to find metric for intermediate-cert in bundle")
	}
}

func TestSecretExporter_ExportMetrics_PKCS12(t *testing.T) {
	metrics.Init(true)

	// Generate certificates
	caCert := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName:   "pkcs12-ca",
		Organization: "test-org",
		Country:      "US",
		Province:     "CA",
		Days:         365,
		IsCA:         true,
	})

	clientCert := testutil.GenerateSignedCertificate(t, testutil.CertConfig{
		CommonName:   "pkcs12-client",
		Organization: "test-org",
		Country:      "US",
		Province:     "CA",
		Days:         90,
		IsCA:         false,
	}, caCert)

	// Create PKCS12 bundle without password
	pfxData := testutil.CreatePKCS12Bundle(t, clientCert, []*testutil.CertBundle{caCert}, "")

	exporter := &SecretExporter{}
	exporter.ResetMetrics()

	// Export PKCS12 metrics
	err := exporter.ExportMetrics(pfxData, "keystore.p12", "pkcs12-secret", "test-namespace", "")
	if err != nil {
		t.Fatalf("Failed to export PKCS12 metrics: %v", err)
	}

	// Verify metrics
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	foundClient := false
	foundCA := false

	for _, mf := range mfs {
		if mf.GetName() == "cert_exporter_secret_expires_in_seconds" {
			for _, metric := range mf.GetMetric() {
				labels := getLabelMap(metric)
				if labels["secret_name"] == "pkcs12-secret" {
					if labels["cn"] == "pkcs12-client" {
						foundClient = true
					}
					if labels["cn"] == "pkcs12-ca" {
						foundCA = true
					}
				}
			}
		}
	}

	if !foundClient {
		t.Error("Expected to find metric for pkcs12-client in PKCS12 bundle")
	}
	if !foundCA {
		t.Error("Expected to find metric for pkcs12-ca in PKCS12 bundle")
	}
}

func TestSecretExporter_ExportMetrics_PKCS12WithPassword(t *testing.T) {
	metrics.Init(true)

	// Generate certificates
	caCert := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName:   "password-ca",
		Organization: "test-org",
		Country:      "US",
		Province:     "CA",
		Days:         365,
		IsCA:         true,
	})

	clientCert := testutil.GenerateSignedCertificate(t, testutil.CertConfig{
		CommonName:   "password-client",
		Organization: "test-org",
		Country:      "US",
		Province:     "CA",
		Days:         90,
		IsCA:         false,
	}, caCert)

	// Create PKCS12 bundle with password
	password := "test-password"
	pfxData := testutil.CreatePKCS12Bundle(t, clientCert, []*testutil.CertBundle{caCert}, password)

	exporter := &SecretExporter{}
	exporter.ResetMetrics()

	// Export PKCS12 metrics with correct password
	err := exporter.ExportMetrics(pfxData, "secure.p12", "secure-secret", "test-namespace", password)
	if err != nil {
		t.Fatalf("Failed to export PKCS12 metrics with password: %v", err)
	}

	// Verify metrics
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	found := false
	for _, mf := range mfs {
		if mf.GetName() == "cert_exporter_secret_expires_in_seconds" {
			for _, metric := range mf.GetMetric() {
				labels := getLabelMap(metric)
				if labels["secret_name"] == "secure-secret" && labels["cn"] == "password-client" {
					found = true
				}
			}
		}
	}

	if !found {
		t.Error("Expected to find metric for password-protected PKCS12")
	}
}

func TestSecretExporter_ExportMetrics_InvalidCert(t *testing.T) {
	metrics.Init(true)

	exporter := &SecretExporter{}
	exporter.ResetMetrics()

	// Try to export invalid certificate data
	err := exporter.ExportMetrics([]byte("not a valid certificate"), "invalid.crt", "invalid-secret", "test-namespace", "")
	if err == nil {
		t.Error("Expected error when exporting invalid certificate data")
	}
}

func TestSecretExporter_ResetMetrics(t *testing.T) {
	metrics.Init(true)

	// Generate and export test certificate
	cert := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName: "reset-test", Organization: "test-org", Country: "US", Province: "CA", Days: 30,
	})

	exporter := &SecretExporter{}
	exporter.ResetMetrics()

	err := exporter.ExportMetrics(cert.CertPEM, "tls.crt", "reset-secret", "test-namespace", "")
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
		if mf.GetName() == "cert_exporter_secret_expires_in_seconds" {
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
		if mf.GetName() == "cert_exporter_secret_expires_in_seconds" {
			if len(mf.GetMetric()) > 0 {
				t.Error("Expected metrics to be reset, but found metrics")
			}
		}
	}
}
