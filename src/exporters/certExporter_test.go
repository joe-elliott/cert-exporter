package exporters

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/joe-elliott/cert-exporter/internal/testutil"
	"github.com/joe-elliott/cert-exporter/src/metrics"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// TestCertExporter_SameCNDifferentSerial ensures file-based multi-PEM bundles
// with identical cn/issuer keep distinct series via serial.
func TestCertExporter_SameCNDifferentSerial(t *testing.T) {
	testRegistry := prometheus.NewRegistry()
	metrics.Init(true, testRegistry, true)

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "service-ca.crt")

	newer := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName: "service-ca", Organization: "org", Country: "US", Province: "CA", Days: 365, IsCA: true,
	})
	older := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName: "service-ca", Organization: "org", Country: "US", Province: "CA", Days: 30, IsCA: true,
	})
	testutil.WriteCertToFile(t, testutil.CreateCertBundle(newer, older), certFile)

	exporter := &CertExporter{}
	exporter.ResetMetrics()
	if err := exporter.ExportMetrics(certFile, "node1"); err != nil {
		t.Fatalf("ExportMetrics: %v", err)
	}

	mfs, err := testRegistry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}

	serials := map[string]struct{}{}
	for _, mf := range mfs {
		if mf.GetName() != "cert_exporter_cert_expires_in_seconds" {
			continue
		}
		for _, metric := range mf.GetMetric() {
			labels := getLabelMap(metric)
			if labels["filename"] != certFile || labels["cn"] != "service-ca" {
				continue
			}
			if labels["serial"] == "" {
				t.Error("expected serial label")
			}
			serials[labels["serial"]] = struct{}{}
		}
	}
	if len(serials) != 2 {
		t.Fatalf("expected 2 series, got %d: %v", len(serials), serials)
	}
}

func TestCertExporter_ExportMetrics(t *testing.T) {
	// Create a custom registry for this test to avoid collisions
	testRegistry := prometheus.NewRegistry()
	metrics.Init(true, testRegistry, false)

	tests := []struct {
		name     string
		setup    func(t *testing.T) string
		nodeName string
		wantErr  bool
	}{
		{
			name: "valid PEM certificate",
			setup: func(t *testing.T) string {
				tmpDir := testutil.CreateTempCertDir(t)
				certFile := tmpDir + "/test.crt"

				cert := testutil.GenerateCertificate(t, testutil.CertConfig{
					CommonName:   "test-cert",
					Organization: "test-org",
					Country:      "US",
					Province:     "CA",
					Days:         30,
					IsCA:         false,
				})

				testutil.WriteCertToFile(t, cert.CertPEM, certFile)
				return certFile
			},
			nodeName: "test-node",
			wantErr:  false,
		},
		{
			name: "certificate bundle with multiple certs",
			setup: func(t *testing.T) string {
				tmpDir := testutil.CreateTempCertDir(t)
				certFile := tmpDir + "/bundle.crt"

				root := testutil.GenerateCertificate(t, testutil.CertConfig{
					CommonName:   "root-ca",
					Organization: "test-org",
					Country:      "US",
					Province:     "CA",
					Days:         365,
					IsCA:         true,
				})

				intermediate := testutil.GenerateSignedCertificate(t, testutil.CertConfig{
					CommonName:   "intermediate",
					Organization: "test-org",
					Country:      "US",
					Province:     "CA",
					Days:         180,
					IsCA:         false,
				}, root)

				bundle := testutil.CreateCertBundle(intermediate, root)
				testutil.WriteCertToFile(t, bundle, certFile)
				return certFile
			},
			nodeName: "test-node",
			wantErr:  false,
		},
		{
			name: "invalid certificate file",
			setup: func(t *testing.T) string {
				tmpDir := testutil.CreateTempCertDir(t)
				certFile := tmpDir + "/invalid.crt"
				err := os.WriteFile(certFile, []byte("not a certificate"), 0644)
				if err != nil {
					t.Fatal(err)
				}
				return certFile
			},
			nodeName: "test-node",
			wantErr:  true,
		},
		{
			name: "non-existent file",
			setup: func(t *testing.T) string {
				return "/tmp/non-existent-cert.crt"
			},
			nodeName: "test-node",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := &CertExporter{}
			exporter.ResetMetrics()

			certFile := tt.setup(t)
			err := exporter.ExportMetrics(certFile, tt.nodeName)

			if (err != nil) != tt.wantErr {
				t.Errorf("ExportMetrics() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify metrics were set
				mfs, err := testRegistry.Gather()
				if err != nil {
					t.Fatalf("Failed to gather metrics: %v", err)
				}

				foundExpiry := false
				foundNotAfter := false
				foundNotBefore := false

				for _, mf := range mfs {
					switch mf.GetName() {
					case "cert_exporter_cert_expires_in_seconds":
						foundExpiry = true
						if len(mf.GetMetric()) == 0 {
							t.Error("Expected cert_expires_in_seconds metric to have values")
						}
					case "cert_exporter_cert_not_after_timestamp":
						foundNotAfter = true
					case "cert_exporter_cert_not_before_timestamp":
						foundNotBefore = true
					}
				}

				if !foundExpiry {
					t.Error("cert_expires_in_seconds metric not found")
				}
				if !foundNotAfter {
					t.Error("cert_not_after_timestamp metric not found")
				}
				if !foundNotBefore {
					t.Error("cert_not_before_timestamp metric not found")
				}
			}
		})
	}
}

func TestCertExporter_MetricsValues(t *testing.T) {
	// Create a custom registry for this test to avoid collisions
	testRegistry := prometheus.NewRegistry()
	metrics.Init(true, testRegistry, false)

	tmpDir := testutil.CreateTempCertDir(t)
	certFile := tmpDir + "/test.crt"

	// Create a certificate that expires in 30 days
	days := 30
	cert := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName:   "metrics-test",
		Organization: "test-org",
		Country:      "US",
		Province:     "CA",
		Days:         days,
		IsCA:         false,
	})

	testutil.WriteCertToFile(t, cert.CertPEM, certFile)

	exporter := &CertExporter{}
	exporter.ResetMetrics()

	err := exporter.ExportMetrics(certFile, "test-node")
	if err != nil {
		t.Fatalf("ExportMetrics() failed: %v", err)
	}

	// Gather metrics
	mfs, err := testRegistry.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	// Find the expiry metric
	var expiryMetric *dto.Metric
	for _, mf := range mfs {
		if mf.GetName() == "cert_exporter_cert_expires_in_seconds" {
			if len(mf.GetMetric()) > 0 {
				expiryMetric = mf.GetMetric()[0]
				break
			}
		}
	}

	if expiryMetric == nil {
		t.Fatal("Could not find cert_expires_in_seconds metric")
	}

	// Check that the expiry is approximately correct (within 1 day tolerance)
	expectedSeconds := float64(days * 24 * 60 * 60)
	actualSeconds := expiryMetric.GetGauge().GetValue()
	tolerance := float64(24 * 60 * 60) // 1 day tolerance

	if actualSeconds < expectedSeconds-tolerance || actualSeconds > expectedSeconds+tolerance {
		t.Errorf("Expiry metric value = %v, expected approximately %v (±%v)", actualSeconds, expectedSeconds, tolerance)
	}

	// Verify labels
	labels := expiryMetric.GetLabel()
	labelMap := make(map[string]string)
	for _, label := range labels {
		labelMap[label.GetName()] = label.GetValue()
	}

	if labelMap["cn"] != "metrics-test" {
		t.Errorf("Expected cn=metrics-test, got %v", labelMap["cn"])
	}
	if labelMap["nodename"] != "test-node" {
		t.Errorf("Expected nodename=test-node, got %v", labelMap["nodename"])
	}
}

func TestCertExporter_PKCS12(t *testing.T) {
	// Create a custom registry for this test to avoid collisions
	testRegistry := prometheus.NewRegistry()
	metrics.Init(true, testRegistry, false)

	tmpDir := testutil.CreateTempCertDir(t)
	certFile := tmpDir + "/test.p12"

	// Create a certificate and CA
	root := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName:   "root-ca",
		Organization: "test-org",
		Country:      "US",
		Province:     "CA",
		Days:         365,
		IsCA:         true,
	})

	cert := testutil.GenerateSignedCertificate(t, testutil.CertConfig{
		CommonName:   "pkcs12-test",
		Organization: "test-org",
		Country:      "US",
		Province:     "CA",
		Days:         30,
		IsCA:         false,
	}, root)

	// Create PKCS12 bundle
	pfxData := testutil.CreatePKCS12Bundle(t, cert, []*testutil.CertBundle{root}, "")
	err := os.WriteFile(certFile, pfxData, 0644)
	if err != nil {
		t.Fatalf("Failed to write PKCS12 file: %v", err)
	}

	exporter := &CertExporter{}
	exporter.ResetMetrics()

	err = exporter.ExportMetrics(certFile, "test-node")
	if err != nil {
		t.Fatalf("ExportMetrics() failed for PKCS12: %v", err)
	}

	// Verify metrics were created
	mfs, err := testRegistry.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	foundMetric := false
	for _, mf := range mfs {
		if mf.GetName() == "cert_exporter_cert_expires_in_seconds" {
			if len(mf.GetMetric()) > 0 {
				foundMetric = true
				break
			}
		}
	}

	if !foundMetric {
		t.Error("Expected metrics for PKCS12 certificate")
	}
}

func TestCertExporter_ResetMetrics(t *testing.T) {
	// Create a custom registry for this test to avoid collisions
	testRegistry := prometheus.NewRegistry()
	metrics.Init(true, testRegistry, false)

	tmpDir := testutil.CreateTempCertDir(t)
	certFile := tmpDir + "/test.crt"

	cert := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName:   "reset-test",
		Organization: "test-org",
		Country:      "US",
		Province:     "CA",
		Days:         30,
		IsCA:         false,
	})

	testutil.WriteCertToFile(t, cert.CertPEM, certFile)

	exporter := &CertExporter{}

	// Export metrics
	err := exporter.ExportMetrics(certFile, "test-node")
	if err != nil {
		t.Fatalf("ExportMetrics() failed: %v", err)
	}

	// Verify metrics exist
	mfs, err := testRegistry.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	metricsBefore := 0
	for _, mf := range mfs {
		if mf.GetName() == "cert_exporter_cert_expires_in_seconds" {
			metricsBefore = len(mf.GetMetric())
			break
		}
	}

	if metricsBefore == 0 {
		t.Fatal("Expected metrics to exist before reset")
	}

	// Reset metrics
	exporter.ResetMetrics()

	// Wait a bit for reset to take effect
	time.Sleep(10 * time.Millisecond)

	// Verify metrics were reset
	mfs, err = testRegistry.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	metricsAfter := 0
	for _, mf := range mfs {
		if mf.GetName() == "cert_exporter_cert_expires_in_seconds" {
			metricsAfter = len(mf.GetMetric())
			break
		}
	}

	if metricsAfter != 0 {
		t.Errorf("Expected metrics to be reset, but found %d metrics", metricsAfter)
	}
}

// TestCertExporter_PasswordProtectedKeystore pins the path from the exporter's
// Password field, which --cert-password-file feeds, down into the parser.
// Without it, passing an empty password there would go unnoticed.
func TestCertExporter_PasswordProtectedKeystore(t *testing.T) {
	testRegistry := prometheus.NewRegistry()
	metrics.Init(true, testRegistry, false)

	const password = "store-password"
	bundle := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName: "keystore-cert",
		Days:       30,
		IsCA:       true,
	})
	store := jksWithTrustedCerts(t, password, map[string]*testutil.CertBundle{"only": bundle})

	certFile := filepath.Join(testutil.CreateTempCertDir(t), "store.jks")
	if err := os.WriteFile(certFile, store, 0o600); err != nil {
		t.Fatalf("Failed to write keystore: %v", err)
	}

	exporter := &CertExporter{Password: password}
	exporter.ResetMetrics()

	if err := exporter.ExportMetrics(certFile, "test-node"); err != nil {
		t.Fatalf("ExportMetrics() failed for a password-protected keystore: %v", err)
	}

	mfs, err := testRegistry.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	found := false
	for _, mf := range mfs {
		if mf.GetName() != "cert_exporter_cert_expires_in_seconds" {
			continue
		}
		for _, metric := range mf.GetMetric() {
			for _, label := range metric.GetLabel() {
				if label.GetName() == "cn" && label.GetValue() == "keystore-cert" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Error("Expected a metric for keystore-cert; the password did not reach the parser")
	}

	// Without the password the same file must fail rather than export nothing
	// quietly.
	if err := (&CertExporter{}).ExportMetrics(certFile, "test-node"); err == nil {
		t.Error("ExportMetrics() with no password returned nil, want an error")
	}
}
