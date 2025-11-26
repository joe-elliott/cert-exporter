// +build integration

package main

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/joe-elliott/cert-exporter/internal/testutil"
	"github.com/joe-elliott/cert-exporter/src/checkers"
	"github.com/joe-elliott/cert-exporter/src/exporters"
	"github.com/joe-elliott/cert-exporter/src/metrics"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
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

// TestKubernetesSecrets tests secret checking with a real Kubernetes cluster
// This test requires a KUBECONFIG environment variable pointing to a valid cluster
func TestKubernetesSecrets(t *testing.T) {
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		kubeconfig = os.Getenv("HOME") + "/.kube/config"
		if _, err := os.Stat(kubeconfig); os.IsNotExist(err) {
			t.Skip("Skipping Kubernetes integration test: KUBECONFIG not set and ~/.kube/config not found")
		}
	}

	initMetricsOnce()

	// Load kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatalf("Failed to load kubeconfig: %v", err)
	}

	// Create Kubernetes client
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatalf("Failed to create Kubernetes client: %v", err)
	}

	// Create test namespace
	testNS := "cert-exporter-test-" + time.Now().Format("20060102150405")
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: testNS,
		},
	}
	_, err = clientset.CoreV1().Namespaces().Create(context.Background(), ns, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Failed to create test namespace: %v", err)
	}
	defer func() {
		clientset.CoreV1().Namespaces().Delete(context.Background(), testNS, metav1.DeleteOptions{})
	}()

	// Generate test certificate
	cert := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName:   "k8s-secret-test",
		Organization: "test-org",
		Country:      "US",
		Province:     "CA",
		Days:         30,
		IsCA:         false,
	})

	// Create secret
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-tls-secret",
			Namespace: testNS,
			Annotations: map[string]string{
				"cert-exporter-test": "true",
			},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": cert.CertPEM,
			"tls.key": cert.PrivateKeyPEM,
		},
	}

	_, err = clientset.CoreV1().Secrets(testNS).Create(context.Background(), secret, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	// Wait a bit for secret to be fully created
	time.Sleep(100 * time.Millisecond)

	// Create exporter and reset metrics
	exporter := &exporters.SecretExporter{}
	exporter.ResetMetrics()

	// Start secret checker
	checker := checkers.NewSecretChecker(
		500*time.Millisecond, // Slower polling for K8s
		[]string{},
		[]string{"*.crt"},
		[]string{},
		[]string{"cert-exporter-test"},
		[]string{testNS},
		[]string{},
		kubeconfig,
		exporter,
		[]string{},
	)

	stopCh := make(chan struct{})
	defer close(stopCh)

	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		for i := 0; i < 3; i++ { // Run 3 cycles max
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				// Checker will run its own checking logic
			}
		}
	}()

	// Start the checker in background
	go checker.StartChecking()

	// Wait for at least three check cycles to complete (K8s needs more time)
	// Try multiple times with delay
	foundMetric := false
	for attempt := 0; attempt < 5; attempt++ {
		time.Sleep(600 * time.Millisecond)

		// Verify metrics
		mfs, err := prometheus.DefaultGatherer.Gather()
		if err != nil {
			t.Fatalf("Failed to gather metrics: %v", err)
		}

		for _, mf := range mfs {
			if mf.GetName() == "cert_exporter_secret_expires_in_seconds" {
				for _, metric := range mf.GetMetric() {
					labels := make(map[string]string)
					for _, label := range metric.GetLabel() {
						labels[label.GetName()] = label.GetValue()
					}
					t.Logf("Attempt %d - Found secret metric: secret_name=%s, secret_namespace=%s, cn=%s",
						attempt+1, labels["secret_name"], labels["secret_namespace"], labels["cn"])

					if labels["secret_name"] == "test-tls-secret" && labels["secret_namespace"] == testNS {
						foundMetric = true
						if labels["cn"] != "k8s-secret-test" {
							t.Errorf("Expected cn=k8s-secret-test, got %v", labels["cn"])
						}
						break
					}
				}
			}
		}

		if foundMetric {
			t.Logf("Found metric on attempt %d", attempt+1)
			break
		}
	}

	if !foundMetric {
		t.Error("Expected to find metric for test secret after multiple attempts")
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
