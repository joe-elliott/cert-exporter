package checkers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/joe-elliott/cert-exporter/internal/testutil"
	"github.com/joe-elliott/cert-exporter/src/exporters"
	"github.com/joe-elliott/cert-exporter/src/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

func TestPeriodicCertChecker_GetMatches(t *testing.T) {
	tmpDir := testutil.CreateTempCertDir(t)

	// Create test certificate files in different directories
	cert1 := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName: "test1", Organization: "org", Country: "US", Province: "CA", Days: 30,
	})
	cert2 := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName: "test2", Organization: "org", Country: "US", Province: "CA", Days: 30,
	})
	cert3 := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName: "test3", Organization: "org", Country: "US", Province: "CA", Days: 30,
	})

	testutil.WriteCertToFile(t, cert1.CertPEM, filepath.Join(tmpDir, "dir1", "cert1.crt"))
	testutil.WriteCertToFile(t, cert2.CertPEM, filepath.Join(tmpDir, "dir1", "cert2.crt"))
	testutil.WriteCertToFile(t, cert3.CertPEM, filepath.Join(tmpDir, "dir2", "cert3.pem"))
	testutil.WriteCertToFile(t, cert1.CertPEM, filepath.Join(tmpDir, "dir2", "excluded.crt"))

	tests := []struct {
		name           string
		includeGlobs   []string
		excludeGlobs   []string
		expectedCount  int
		expectedFiles  []string
		notExpected    []string
	}{
		{
			name:          "single include glob - all .crt files",
			includeGlobs:  []string{tmpDir + "/**/*.crt"},
			excludeGlobs:  []string{},
			expectedCount: 3,
			expectedFiles: []string{"cert1.crt", "cert2.crt", "excluded.crt"},
		},
		{
			name:          "include all, exclude one",
			includeGlobs:  []string{tmpDir + "/**/*.crt"},
			excludeGlobs:  []string{tmpDir + "/**/excluded.crt"},
			expectedCount: 2,
			expectedFiles: []string{"cert1.crt", "cert2.crt"},
			notExpected:   []string{"excluded.crt"},
		},
		{
			name:          "include specific directory",
			includeGlobs:  []string{tmpDir + "/dir1/*.crt"},
			excludeGlobs:  []string{},
			expectedCount: 2,
			expectedFiles: []string{"cert1.crt", "cert2.crt"},
			notExpected:   []string{"cert3.pem"},
		},
		{
			name:          "include .pem files",
			includeGlobs:  []string{tmpDir + "/**/*.pem"},
			excludeGlobs:  []string{},
			expectedCount: 1,
			expectedFiles: []string{"cert3.pem"},
		},
		{
			name:          "multiple include globs",
			includeGlobs:  []string{tmpDir + "/dir1/*.crt", tmpDir + "/dir2/*.pem"},
			excludeGlobs:  []string{},
			expectedCount: 3,
			expectedFiles: []string{"cert1.crt", "cert2.crt", "cert3.pem"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := NewCertChecker(time.Hour, tt.includeGlobs, tt.excludeGlobs, "test-node", &exporters.CertExporter{})
			matches := checker.getMatches()

			if len(matches) != tt.expectedCount {
				t.Errorf("Expected %d matches, got %d. Matches: %v", tt.expectedCount, len(matches), matches)
			}

			// Check expected files are present
			for _, expected := range tt.expectedFiles {
				found := false
				for _, match := range matches {
					if filepath.Base(match) == expected {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected to find %s in matches, but it was not present", expected)
				}
			}

			// Check not expected files are absent
			for _, notExpected := range tt.notExpected {
				for _, match := range matches {
					if filepath.Base(match) == notExpected {
						t.Errorf("Did not expect to find %s in matches, but it was present", notExpected)
					}
				}
			}
		})
	}
}

func TestPeriodicCertChecker_StartChecking(t *testing.T) {
	testRegistry := prometheus.NewRegistry()
	metrics.Init(true, testRegistry, false)

	tmpDir := testutil.CreateTempCertDir(t)

	// Create test certificates
	cert1 := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName: "integration-test-1", Organization: "org", Country: "US", Province: "CA", Days: 30,
	})
	cert2 := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName: "integration-test-2", Organization: "org", Country: "US", Province: "CA", Days: 60,
	})

	testutil.WriteCertToFile(t, cert1.CertPEM, filepath.Join(tmpDir, "cert1.crt"))
	testutil.WriteCertToFile(t, cert2.CertPEM, filepath.Join(tmpDir, "cert2.crt"))

	includeGlobs := []string{tmpDir + "/*.crt"}
	excludeGlobs := []string{}
	checker := NewCertChecker(time.Hour, includeGlobs, excludeGlobs, "test-node", &exporters.CertExporter{})

	// Run a single check cycle (avoids leaking a forever-running StartChecking goroutine)
	checker.checkOnce()

	// Verify metrics were created
	mfs, err := testRegistry.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	foundMetrics := false
	metricCount := 0
	for _, mf := range mfs {
		if mf.GetName() == "cert_exporter_cert_expires_in_seconds" {
			metricCount = len(mf.GetMetric())
			if metricCount >= 2 {
				foundMetrics = true
			}
			break
		}
	}

	if !foundMetrics {
		t.Errorf("Expected to find metrics for 2 certificates, found %d", metricCount)
	}
}

func TestPeriodicCertChecker_DiscoveredAccumulation(t *testing.T) {
	testRegistry := prometheus.NewRegistry()
	metrics.Init(true, testRegistry, false)
	// Discovered is a process-global gauge; zero it so this test is isolated.
	metrics.Discovered.Set(0)

	tmpDir := testutil.CreateTempCertDir(t)

	cert := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName: "disc-test", Organization: "org", Country: "US", Province: "CA", Days: 30,
	})
	testutil.WriteCertToFile(t, cert.CertPEM, filepath.Join(tmpDir, "a.crt"))
	testutil.WriteCertToFile(t, cert.CertPEM, filepath.Join(tmpDir, "b.crt"))
	// Second checker watches a different glob (mirrors cert + kubeconfig in main).
	testutil.WriteCertToFile(t, cert.CertPEM, filepath.Join(tmpDir, "extra.pem"))

	checkerA := NewCertChecker(
		time.Hour,
		[]string{tmpDir + "/*.crt"},
		[]string{},
		"node",
		&exporters.CertExporter{},
	)
	checkerB := NewCertChecker(
		time.Hour,
		[]string{tmpDir + "/*.pem"},
		[]string{},
		"node",
		&exporters.CertExporter{},
	)

	// Both checkers contribute: 2 .crt + 1 .pem = 3 (not a racey overwrite of 2 or 1).
	checkerA.checkOnce()
	checkerB.checkOnce()
	if got := gatherDiscovered(t, testRegistry); got != 3 {
		t.Fatalf("after both checkers: discovered = %v, want 3", got)
	}

	// Re-running must not double-count (delta adjustment).
	checkerA.checkOnce()
	checkerB.checkOnce()
	if got := gatherDiscovered(t, testRegistry); got != 3 {
		t.Fatalf("after re-run: discovered = %v, want 3", got)
	}

	// Removing a file updates the total by this checker's delta only.
	if err := os.Remove(filepath.Join(tmpDir, "b.crt")); err != nil {
		t.Fatal(err)
	}
	checkerA.checkOnce()
	if got := gatherDiscovered(t, testRegistry); got != 2 {
		t.Fatalf("after removing one cert: discovered = %v, want 2", got)
	}
}

func gatherDiscovered(t *testing.T, reg *prometheus.Registry) float64 {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == "cert_exporter_discovered" && len(mf.GetMetric()) > 0 {
			return mf.GetMetric()[0].GetGauge().GetValue()
		}
	}
	t.Fatal("cert_exporter_discovered not found")
	return 0
}

func TestPeriodicCertChecker_ErrorHandling(t *testing.T) {
	testRegistry := prometheus.NewRegistry()
	metrics.Init(true, testRegistry, false)

	// Capture error_total before this test; the counter is process-global.
	var errorCountBefore float64
	if mfs, err := testRegistry.Gather(); err == nil {
		for _, mf := range mfs {
			if mf.GetName() == "cert_exporter_error_total" && len(mf.GetMetric()) > 0 {
				errorCountBefore = mf.GetMetric()[0].GetCounter().GetValue()
			}
		}
	}

	tmpDir := testutil.CreateTempCertDir(t)

	// Create a valid certificate
	cert := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName: "valid-cert", Organization: "org", Country: "US", Province: "CA", Days: 30,
	})
	testutil.WriteCertToFile(t, cert.CertPEM, filepath.Join(tmpDir, "valid.crt"))

	// Create an invalid certificate file (plaintext garbage — not PEM or PKCS#12)
	invalidFile := filepath.Join(tmpDir, "invalid.crt")
	err := os.WriteFile(invalidFile, []byte("not a valid certificate"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	includeGlobs := []string{tmpDir + "/*.crt"}
	nodeName := "test-node-error-" + filepath.Base(tmpDir)
	checker := NewCertChecker(time.Hour, includeGlobs, []string{}, nodeName, &exporters.CertExporter{})

	// Single synchronous cycle: invalid cert should error, valid cert should still export
	checker.checkOnce()

	mfs, err := testRegistry.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	var errorCount float64
	var validMetricFound bool
	for _, mf := range mfs {
		switch mf.GetName() {
		case "cert_exporter_error_total":
			if len(mf.GetMetric()) > 0 {
				errorCount = mf.GetMetric()[0].GetCounter().GetValue()
			}
		case "cert_exporter_cert_expires_in_seconds":
			for _, metric := range mf.GetMetric() {
				labels := make(map[string]string)
				for _, label := range metric.GetLabel() {
					labels[label.GetName()] = label.GetValue()
				}
				if labels["cn"] == "valid-cert" && labels["nodename"] == nodeName {
					validMetricFound = true
				}
			}
		}
	}

	if errorCount < errorCountBefore+1 {
		t.Errorf("Expected error_total to increase by at least 1 (before=%v, after=%v)", errorCountBefore, errorCount)
	}

	if !validMetricFound {
		t.Error("Expected to find metrics for valid certificate despite error in invalid certificate")
	}

	// Also verify ExportMetrics surfaces a stable parse failure for invalid text
	// (not a brittle PKCS#12 ASN.1 detail that changes across crypto/asn1 versions).
	exportErr := (&exporters.CertExporter{}).ExportMetrics(invalidFile, nodeName)
	if exportErr == nil {
		t.Fatal("Expected ExportMetrics to fail for invalid certificate text")
	}
	if !strings.Contains(exportErr.Error(), "failed to parse as pem, pkcs12 or jks") {
		t.Errorf("Expected parse failure wrapper, got: %v", exportErr)
	}
}
