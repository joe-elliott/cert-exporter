package exporters

import (
	"os"
	"testing"
	"time"

	"github.com/joe-elliott/cert-exporter/internal/testutil"
	"github.com/joe-elliott/cert-exporter/src/metrics"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestCertExporter_ExportMetrics(t *testing.T) {
	// Initialize metrics
	metrics.Init(true)

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
				mfs, err := prometheus.DefaultGatherer.Gather()
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
	// Initialize metrics
	metrics.Init(true)

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
	mfs, err := prometheus.DefaultGatherer.Gather()
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
	// Initialize metrics
	metrics.Init(true)

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
	mfs, err := prometheus.DefaultGatherer.Gather()
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
	// Initialize metrics
	metrics.Init(true)

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
	mfs, err := prometheus.DefaultGatherer.Gather()
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
	mfs, err = prometheus.DefaultGatherer.Gather()
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
