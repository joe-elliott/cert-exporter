package exporters

import (
	"encoding/base64"
	"path/filepath"
	"testing"

	"github.com/joe-elliott/cert-exporter/internal/testutil"
	"github.com/joe-elliott/cert-exporter/src/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

func TestKubeConfigExporter_ExportMetrics(t *testing.T) {
	// Initialize metrics
	metrics.Init(true)

	tests := []struct {
		name     string
		setup    func(t *testing.T) string
		nodeName string
		wantErr  bool
	}{
		{
			name: "kubeconfig with certificate files",
			setup: func(t *testing.T) string {
				tmpDir := testutil.CreateTempCertDir(t)
				kubeConfigFile := filepath.Join(tmpDir, "kubeconfig")
				certDir := filepath.Join(tmpDir, "certs")

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
					CommonName:   "kubernetes-client",
					Organization: "system:masters",
					Country:      "US",
					Province:     "CA",
					Days:         365,
				}, caCert)

				// Write certificates to files
				caCertFile := filepath.Join(certDir, "ca.crt")
				clientCertFile := filepath.Join(certDir, "client.crt")
				clientKeyFile := filepath.Join(certDir, "client.key")

				testutil.WriteCertToFile(t, caCert.CertPEM, caCertFile)
				testutil.WriteCertToFile(t, clientCert.CertPEM, clientCertFile)
				testutil.WriteKeyToFile(t, clientCert.PrivateKeyPEM, clientKeyFile)

				// Create kubeconfig with relative paths
				builder := testutil.NewKubeConfigBuilder()
				builder.AddClusterWithFile("cluster1", "https://kubernetes.example.com", "certs/ca.crt")
				builder.AddUserWithFile("user1", "certs/client.crt", "certs/client.key")
				builder.Build(t, kubeConfigFile)

				return kubeConfigFile
			},
			nodeName: "test-node",
			wantErr:  false,
		},
		{
			name: "kubeconfig with embedded certificate data",
			setup: func(t *testing.T) string {
				tmpDir := testutil.CreateTempCertDir(t)
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
					CommonName:   "kubernetes-client",
					Organization: "system:masters",
					Country:      "US",
					Province:     "CA",
					Days:         365,
				}, caCert)

				// Encode certificates as base64
				caCertData := base64.StdEncoding.EncodeToString(caCert.CertPEM)
				clientCertData := base64.StdEncoding.EncodeToString(clientCert.CertPEM)
				clientKeyData := base64.StdEncoding.EncodeToString(clientCert.PrivateKeyPEM)

				// Create kubeconfig with embedded data
				builder := testutil.NewKubeConfigBuilder()
				builder.AddClusterWithData("cluster2", "https://kubernetes.example.com", caCertData)
				builder.AddUserWithData("user2", clientCertData, clientKeyData)
				builder.Build(t, kubeConfigFile)

				return kubeConfigFile
			},
			nodeName: "test-node",
			wantErr:  false,
		},
		{
			name: "kubeconfig with mixed file and embedded certs",
			setup: func(t *testing.T) string {
				tmpDir := testutil.CreateTempCertDir(t)
				kubeConfigFile := filepath.Join(tmpDir, "kubeconfig")
				certDir := filepath.Join(tmpDir, "certs")

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
					CommonName:   "kubernetes-client",
					Organization: "system:masters",
					Country:      "US",
					Province:     "CA",
					Days:         365,
				}, caCert)

				// Write CA cert to file
				caCertFile := filepath.Join(certDir, "ca.crt")
				testutil.WriteCertToFile(t, caCert.CertPEM, caCertFile)

				// Encode client cert as base64
				clientCertData := base64.StdEncoding.EncodeToString(clientCert.CertPEM)
				clientKeyData := base64.StdEncoding.EncodeToString(clientCert.PrivateKeyPEM)

				// Create kubeconfig
				builder := testutil.NewKubeConfigBuilder()
				builder.AddClusterWithFile("cluster1", "https://kubernetes.example.com", "certs/ca.crt")
				builder.AddUserWithData("user1", clientCertData, clientKeyData)
				builder.Build(t, kubeConfigFile)

				return kubeConfigFile
			},
			nodeName: "test-node",
			wantErr:  false,
		},
		{
			name: "invalid kubeconfig file",
			setup: func(t *testing.T) string {
				tmpDir := testutil.CreateTempCertDir(t)
				kubeConfigFile := filepath.Join(tmpDir, "invalid-kubeconfig")
				testutil.WriteCertToFile(t, []byte("not a valid kubeconfig"), kubeConfigFile)
				return kubeConfigFile
			},
			nodeName: "test-node",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := &KubeConfigExporter{}
			exporter.ResetMetrics()

			kubeConfigFile := tt.setup(t)
			err := exporter.ExportMetrics(kubeConfigFile, tt.nodeName)

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
					case "cert_exporter_kubeconfig_expires_in_seconds":
						foundExpiry = true
						if len(mf.GetMetric()) == 0 {
							t.Error("Expected kubeconfig_expires_in_seconds metric to have values")
						}
						// Verify labels
						for _, metric := range mf.GetMetric() {
							labels := make(map[string]string)
							for _, label := range metric.GetLabel() {
								labels[label.GetName()] = label.GetValue()
							}
							if labels["type"] != "cluster" && labels["type"] != "user" {
								t.Errorf("Expected type label to be 'cluster' or 'user', got %v", labels["type"])
							}
							if labels["nodename"] != tt.nodeName {
								t.Errorf("Expected nodename=%v, got %v", tt.nodeName, labels["nodename"])
							}
						}
					case "cert_exporter_kubeconfig_not_after_timestamp":
						foundNotAfter = true
					case "cert_exporter_kubeconfig_not_before_timestamp":
						foundNotBefore = true
					}
				}

				if !foundExpiry {
					t.Error("kubeconfig_expires_in_seconds metric not found")
				}
				if !foundNotAfter {
					t.Error("kubeconfig_not_after_timestamp metric not found")
				}
				if !foundNotBefore {
					t.Error("kubeconfig_not_before_timestamp metric not found")
				}
			}
		})
	}
}

func TestKubeConfigExporter_MetricsLabels(t *testing.T) {
	// Initialize metrics
	metrics.Init(true)

	tmpDir := testutil.CreateTempCertDir(t)
	kubeConfigFile := filepath.Join(tmpDir, "kubeconfig")
	certDir := filepath.Join(tmpDir, "certs")

	// Generate certificates
	caCert := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName:   "test-ca",
		Organization: "test-org",
		Country:      "US",
		Province:     "CA",
		Days:         365,
		IsCA:         true,
	})

	clientCert := testutil.GenerateSignedCertificate(t, testutil.CertConfig{
		CommonName:   "test-client",
		Organization: "test-org",
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

	// Create kubeconfig with specific names
	builder := testutil.NewKubeConfigBuilder()
	builder.AddClusterWithFile("my-cluster", "https://example.com", "certs/ca.crt")
	builder.AddUserWithFile("my-user", "certs/client.crt", "certs/client.key")
	builder.Build(t, kubeConfigFile)

	exporter := &KubeConfigExporter{}
	exporter.ResetMetrics()

	err := exporter.ExportMetrics(kubeConfigFile, "my-node")
	if err != nil {
		t.Fatalf("ExportMetrics() failed: %v", err)
	}

	// Verify metric labels
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	for _, mf := range mfs {
		if mf.GetName() == "cert_exporter_kubeconfig_expires_in_seconds" {
			foundCluster := false
			foundUser := false

			for _, metric := range mf.GetMetric() {
				labels := make(map[string]string)
				for _, label := range metric.GetLabel() {
					labels[label.GetName()] = label.GetValue()
				}

				if labels["type"] == "cluster" && labels["name"] == "my-cluster" {
					foundCluster = true
					if labels["cn"] != "test-ca" {
						t.Errorf("Expected cluster cn=test-ca, got %v", labels["cn"])
					}
				}

				if labels["type"] == "user" && labels["name"] == "my-user" {
					foundUser = true
					if labels["cn"] != "test-client" {
						t.Errorf("Expected user cn=test-client, got %v", labels["cn"])
					}
				}
			}

			if !foundCluster {
				t.Error("Expected to find cluster metric with name=my-cluster")
			}
			if !foundUser {
				t.Error("Expected to find user metric with name=my-user")
			}
		}
	}
}
