package exporters

import (
	"encoding/base64"
	"testing"

	"github.com/joe-elliott/cert-exporter/internal/testutil"
	"github.com/joe-elliott/cert-exporter/src/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

func TestAwsExporter_ExportMetrics(t *testing.T) {
	metrics.Init(true)

	// Generate test certificate
	cert := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName:   "test-aws-cert",
		Organization: "test-org",
		Country:      "US",
		Province:     "CA",
		Days:         30,
		IsCA:         false,
	})

	// Base64 encode the certificate (as AWS Secrets Manager does)
	base64Cert := base64.StdEncoding.EncodeToString(cert.CertPEM)

	exporter := &AwsExporter{}
	exporter.ResetMetrics()

	// Export metrics
	err := exporter.ExportMetrics(base64Cert, "test-secret", "certificate-key")
	if err != nil {
		t.Fatalf("Failed to export metrics: %v", err)
	}

	// Verify metrics were created
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	found := false
	for _, mf := range mfs {
		if mf.GetName() == "cert_exporter_cert_expires_in_seconds_aws" {
			for _, metric := range mf.GetMetric() {
				labels := getLabelMap(metric)
				if labels["cn"] == "test-aws-cert" && labels["secretName"] == "test-secret" {
					found = true
					value := metric.GetGauge().GetValue()
					if value <= 0 {
						t.Errorf("Expected positive expiry seconds, got %v", value)
					}
				}
			}
		}
	}

	if !found {
		t.Error("Expected to find cert_expires_in_seconds_aws metric")
	}
}

func TestAwsExporter_ExportMetrics_InvalidBase64(t *testing.T) {
	metrics.Init(true)

	exporter := &AwsExporter{}
	exporter.ResetMetrics()

	// Try to export invalid base64 data
	err := exporter.ExportMetrics("not-valid-base64!!!", "test-secret", "cert")
	if err == nil {
		t.Error("Expected error when exporting invalid base64 data")
	}
}

func TestAwsExporter_ExportMetrics_InvalidCertificate(t *testing.T) {
	metrics.Init(true)

	exporter := &AwsExporter{}
	exporter.ResetMetrics()

	// Try to export valid base64 but invalid certificate
	invalidData := base64.StdEncoding.EncodeToString([]byte("not a certificate"))
	err := exporter.ExportMetrics(invalidData, "test-secret", "cert")
	if err == nil {
		t.Error("Expected error when exporting invalid certificate")
	}
}

func TestAwsExporter_ResetMetrics(t *testing.T) {
	metrics.Init(true)

	// Generate and export test certificate
	cert := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName: "reset-test", Organization: "test-org", Country: "US", Province: "CA", Days: 30,
	})

	base64Cert := base64.StdEncoding.EncodeToString(cert.CertPEM)

	exporter := &AwsExporter{}
	exporter.ResetMetrics()

	err := exporter.ExportMetrics(base64Cert, "test-secret", "cert")
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
		if mf.GetName() == "cert_exporter_cert_expires_in_seconds_aws" {
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
		if mf.GetName() == "cert_exporter_cert_expires_in_seconds_aws" {
			if len(mf.GetMetric()) > 0 {
				t.Error("Expected metrics to be reset, but found metrics")
			}
		}
	}
}

func TestAwsExporter_MultipleSecrets(t *testing.T) {
	metrics.Init(true)

	// Generate multiple certificates
	cert1 := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName: "aws-cert-1", Organization: "org", Country: "US", Province: "CA", Days: 30,
	})

	cert2 := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName: "aws-cert-2", Organization: "org", Country: "US", Province: "CA", Days: 60,
	})

	exporter := &AwsExporter{}
	exporter.ResetMetrics()

	// Export multiple certificates
	base64Cert1 := base64.StdEncoding.EncodeToString(cert1.CertPEM)
	base64Cert2 := base64.StdEncoding.EncodeToString(cert2.CertPEM)

	err := exporter.ExportMetrics(base64Cert1, "secret-1", "cert1")
	if err != nil {
		t.Fatalf("Failed to export cert1: %v", err)
	}

	err = exporter.ExportMetrics(base64Cert2, "secret-2", "cert2")
	if err != nil {
		t.Fatalf("Failed to export cert2: %v", err)
	}

	// Verify both metrics exist
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	foundCert1 := false
	foundCert2 := false

	for _, mf := range mfs {
		if mf.GetName() == "cert_exporter_cert_expires_in_seconds_aws" {
			for _, metric := range mf.GetMetric() {
				labels := getLabelMap(metric)
				if labels["secretName"] == "secret-1" && labels["cn"] == "aws-cert-1" {
					foundCert1 = true
				}
				if labels["secretName"] == "secret-2" && labels["cn"] == "aws-cert-2" {
					foundCert2 = true
				}
			}
		}
	}

	if !foundCert1 {
		t.Error("Expected to find metric for aws-cert-1")
	}
	if !foundCert2 {
		t.Error("Expected to find metric for aws-cert-2")
	}
}
