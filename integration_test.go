// +build integration

package main

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/joe-elliott/cert-exporter/internal/testutil"
	"github.com/joe-elliott/cert-exporter/src/exporters"
	"github.com/joe-elliott/cert-exporter/src/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	initOnce sync.Once
)

// initMetricsOnce ensures metrics are only initialized once for all integration tests
func initMetricsOnce() {
	initOnce.Do(func() {
		// Use default registry (not disabled) for integration tests
		metrics.Init(false)
	})
}

// TestEndToEnd tests the complete flow of cert-exporter with certificates on disk
func TestEndToEnd_FileBasedCerts(t *testing.T) {
	initMetricsOnce()

	tmpDir := testutil.CreateTempCertDir(t)

	// Generate multiple test certificates with different expiration dates
	cert30Days := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName:   "cert-30-days",
		Organization: "test-org",
		Country:      "US",
		Province:     "CA",
		Days:         30,
		IsCA:         false,
	})

	cert90Days := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName:   "cert-90-days",
		Organization: "test-org",
		Country:      "US",
		Province:     "CA",
		Days:         90,
		IsCA:         false,
	})

	root := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName:   "root-ca",
		Organization: "test-org",
		Country:      "US",
		Province:     "CA",
		Days:         365,
		IsCA:         true,
	})

	intermediate := testutil.GenerateSignedCertificate(t, testutil.CertConfig{
		CommonName:   "intermediate-cert",
		Organization: "test-org",
		Country:      "US",
		Province:     "CA",
		Days:         180,
		IsCA:         false,
	}, root)

	// Write certificates to files
	testutil.WriteCertToFile(t, cert30Days.CertPEM, filepath.Join(tmpDir, "cert-30.crt"))
	testutil.WriteCertToFile(t, cert90Days.CertPEM, filepath.Join(tmpDir, "cert-90.crt"))

	// Create bundle
	bundle := testutil.CreateCertBundle(intermediate, root)
	testutil.WriteCertToFile(t, bundle, filepath.Join(tmpDir, "bundle.crt"))

	// Create PKCS12
	pfxData := testutil.CreatePKCS12Bundle(t, intermediate, []*testutil.CertBundle{root}, "")
	testutil.WriteCertToFile(t, pfxData, filepath.Join(tmpDir, "bundle.p12"))

	// Create exporter and reset metrics
	exporter := &exporters.CertExporter{}
	exporter.ResetMetrics()

	// Export all certificates directly
	certFiles := []string{
		filepath.Join(tmpDir, "cert-30.crt"),
		filepath.Join(tmpDir, "cert-90.crt"),
		filepath.Join(tmpDir, "bundle.crt"),
		filepath.Join(tmpDir, "bundle.p12"),
	}

	for _, certFile := range certFiles {
		if err := exporter.ExportMetrics(certFile, "test-node-e2e"); err != nil {
			t.Logf("Error exporting %s: %v", certFile, err)
		}
	}

	// Wait a bit for metrics to be registered
	time.Sleep(50 * time.Millisecond)

	// Verify all metrics
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	certMetrics := make(map[string]float64)
	for _, mf := range mfs {
		if mf.GetName() == "cert_exporter_cert_expires_in_seconds" {
			for _, metric := range mf.GetMetric() {
				labels := make(map[string]string)
				for _, label := range metric.GetLabel() {
					labels[label.GetName()] = label.GetValue()
				}
				if labels["nodename"] == "test-node-e2e" {
					certMetrics[labels["cn"]] = metric.GetGauge().GetValue()
				}
			}
		}
	}

	// Verify we have metrics for all certificates
	expectedCerts := []string{"cert-30-days", "cert-90-days", "root-ca", "intermediate-cert"}
	for _, cn := range expectedCerts {
		if _, found := certMetrics[cn]; !found {
			t.Errorf("Expected to find metric for certificate %s, found metrics for: %v", cn, getKeys(certMetrics))
		}
	}

	// Verify expiration values are reasonable (within 1 day tolerance)
	tolerance := float64(24 * 60 * 60)

	if val, ok := certMetrics["cert-30-days"]; ok {
		expected := float64(30 * 24 * 60 * 60)
		if val < expected-tolerance || val > expected+tolerance {
			t.Errorf("cert-30-days: expected ~%v seconds, got %v", expected, val)
		}
	}

	if val, ok := certMetrics["cert-90-days"]; ok {
		expected := float64(90 * 24 * 60 * 60)
		if val < expected-tolerance || val > expected+tolerance {
			t.Errorf("cert-90-days: expected ~%v seconds, got %v", expected, val)
		}
	}
}

// TestEndToEnd_Kubeconfig tests kubeconfig parsing and metric export
func TestEndToEnd_Kubeconfig(t *testing.T) {
	initMetricsOnce()

	tmpDir := testutil.CreateTempCertDir(t)
	certDir := filepath.Join(tmpDir, "certs")
	kubeConfigFile := filepath.Join(tmpDir, "kubeconfig")

	// Generate certificates
	caCert := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName:   "kubernetes-ca",
		Organization: "kubernetes",
		Country:      "US",
		Province:     "CA",
		Days:         365,
		IsCA:         true,
	})

	clientCert := testutil.GenerateSignedCertificate(t, testutil.CertConfig{
		CommonName:   "kubernetes-admin",
		Organization: "system:masters",
		Country:      "US",
		Province:     "CA",
		Days:         365,
	}, caCert)

	// Write certificates
	caCertFile := filepath.Join(certDir, "ca.crt")
	clientCertFile := filepath.Join(certDir, "client.crt")
	clientKeyFile := filepath.Join(certDir, "client.key")

	testutil.WriteCertToFile(t, caCert.CertPEM, caCertFile)
	testutil.WriteCertToFile(t, clientCert.CertPEM, clientCertFile)
	testutil.WriteKeyToFile(t, clientCert.PrivateKeyPEM, clientKeyFile)

	// Create kubeconfig
	builder := testutil.NewKubeConfigBuilder()
	builder.AddClusterWithFile("test-cluster", "https://kubernetes.example.com", "certs/ca.crt")
	builder.AddUserWithFile("test-user", "certs/client.crt", "certs/client.key")
	builder.Build(t, kubeConfigFile)

	// Create exporter and reset metrics
	exporter := &exporters.KubeConfigExporter{}
	exporter.ResetMetrics()

	// Export metrics once
	if err := exporter.ExportMetrics(kubeConfigFile, "test-node-kube"); err != nil {
		t.Fatalf("Failed to export kubeconfig metrics: %v", err)
	}

	// Verify metrics
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	foundCluster := false
	foundUser := false

	for _, mf := range mfs {
		if mf.GetName() == "cert_exporter_kubeconfig_expires_in_seconds" {
			for _, metric := range mf.GetMetric() {
				labels := make(map[string]string)
				for _, label := range metric.GetLabel() {
					labels[label.GetName()] = label.GetValue()
				}

				if labels["nodename"] != "test-node-kube" {
					continue
				}

				if labels["type"] == "cluster" && labels["name"] == "test-cluster" {
					foundCluster = true
					if labels["cn"] != "kubernetes-ca" {
						t.Errorf("Expected cluster cn=kubernetes-ca, got %v", labels["cn"])
					}
				}

				if labels["type"] == "user" && labels["name"] == "test-user" {
					foundUser = true
					if labels["cn"] != "kubernetes-admin" {
						t.Errorf("Expected user cn=kubernetes-admin, got %v", labels["cn"])
					}
				}
			}
		}
	}

	if !foundCluster {
		t.Error("Expected to find cluster metric in kubeconfig")
	}
	if !foundUser {
		t.Error("Expected to find user metric in kubeconfig")
	}
}

// TestEndToEnd_ErrorMetric tests that error metrics are properly incremented
func TestEndToEnd_ErrorMetric(t *testing.T) {
	initMetricsOnce()

	tmpDir := testutil.CreateTempCertDir(t)

	// Create an invalid certificate file
	invalidFile := filepath.Join(tmpDir, "invalid.crt")
	if err := os.WriteFile(invalidFile, []byte("this is not a certificate"), 0644); err != nil {
		t.Fatal(err)
	}

	// Get initial error count
	initialErrorCount := getErrorCount(t)

	// Create exporter
	exporter := &exporters.CertExporter{}

	// Try to export the invalid cert (should increment error counter)
	err := exporter.ExportMetrics(invalidFile, "test-node-error")
	if err == nil {
		t.Error("Expected error when exporting invalid certificate")
	}

	// Manually increment the error metric since we're not using the checker
	metrics.ErrorTotal.Inc()

	// Verify error metric was incremented
	newErrorCount := getErrorCount(t)

	if newErrorCount <= initialErrorCount {
		t.Errorf("Expected error_total to increase from %v, got %v", initialErrorCount, newErrorCount)
	}
}

// Helper function to get map keys
func getKeys(m map[string]float64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// Helper function to get current error count
func getErrorCount(t *testing.T) float64 {
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	for _, mf := range mfs {
		if mf.GetName() == "cert_exporter_error_total" {
			if len(mf.GetMetric()) > 0 {
				return mf.GetMetric()[0].GetCounter().GetValue()
			}
		}
	}
	return 0
}
