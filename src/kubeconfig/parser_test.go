package kubeconfig

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/joe-elliott/cert-exporter/internal/testutil"
)

func TestParseKubeConfig_FileBasedCerts(t *testing.T) {
	tmpDir := testutil.CreateTempCertDir(t)
	certDir := filepath.Join(tmpDir, "certs")
	kubeConfigFile := filepath.Join(tmpDir, "kubeconfig")

	// Generate test certificates
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

	// Write certificates to files
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

	// Parse the kubeconfig
	config, err := ParseKubeConfig(kubeConfigFile)
	if err != nil {
		t.Fatalf("Failed to parse kubeconfig: %v", err)
	}

	// Verify clusters
	if len(config.Clusters) != 1 {
		t.Errorf("Expected 1 cluster, got %d", len(config.Clusters))
	}
	if config.Clusters[0].Name != "test-cluster" {
		t.Errorf("Expected cluster name 'test-cluster', got '%s'", config.Clusters[0].Name)
	}
	if config.Clusters[0].Cluster.CertificateAuthority != "certs/ca.crt" {
		t.Errorf("Expected certificate-authority 'certs/ca.crt', got '%s'", config.Clusters[0].Cluster.CertificateAuthority)
	}

	// Verify users
	if len(config.Users) != 1 {
		t.Errorf("Expected 1 user, got %d", len(config.Users))
	}
	if config.Users[0].Name != "test-user" {
		t.Errorf("Expected user name 'test-user', got '%s'", config.Users[0].Name)
	}
	if config.Users[0].User.ClientCertificate != "certs/client.crt" {
		t.Errorf("Expected client-certificate 'certs/client.crt', got '%s'", config.Users[0].User.ClientCertificate)
	}
}

func TestParseKubeConfig_EmbeddedCerts(t *testing.T) {
	tmpDir := testutil.CreateTempCertDir(t)
	kubeConfigFile := filepath.Join(tmpDir, "kubeconfig")

	// Generate test certificates
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

	// Create kubeconfig with embedded cert data
	builder := testutil.NewKubeConfigBuilder()
	builder.AddClusterWithData("test-cluster", "https://kubernetes.example.com", string(caCert.CertPEM))
	builder.AddUserWithData("test-user", string(clientCert.CertPEM), string(clientCert.PrivateKeyPEM))
	builder.Build(t, kubeConfigFile)

	// Parse the kubeconfig
	config, err := ParseKubeConfig(kubeConfigFile)
	if err != nil {
		t.Fatalf("Failed to parse kubeconfig: %v", err)
	}

	// Verify clusters
	if len(config.Clusters) != 1 {
		t.Errorf("Expected 1 cluster, got %d", len(config.Clusters))
	}
	if config.Clusters[0].Cluster.CertificateAuthorityData == "" {
		t.Error("Expected non-empty certificate-authority-data")
	}

	// Verify users
	if len(config.Users) != 1 {
		t.Errorf("Expected 1 user, got %d", len(config.Users))
	}
	if config.Users[0].User.ClientCertificateData == "" {
		t.Error("Expected non-empty client-certificate-data")
	}
}

func TestParseKubeConfig_InvalidFile(t *testing.T) {
	// Test with non-existent file
	_, err := ParseKubeConfig("/nonexistent/kubeconfig")
	if err == nil {
		t.Error("Expected error when parsing non-existent file")
	}

	// Test with invalid YAML
	tmpDir := testutil.CreateTempCertDir(t)
	invalidFile := filepath.Join(tmpDir, "invalid.yaml")
	if err := os.WriteFile(invalidFile, []byte("not: [valid: yaml"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err = ParseKubeConfig(invalidFile)
	if err == nil {
		t.Error("Expected error when parsing invalid YAML")
	}
}

func TestParseKubeConfig_EmptyFile(t *testing.T) {
	tmpDir := testutil.CreateTempCertDir(t)
	emptyFile := filepath.Join(tmpDir, "empty.yaml")
	if err := os.WriteFile(emptyFile, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	config, err := ParseKubeConfig(emptyFile)
	if err != nil {
		t.Fatalf("Failed to parse empty kubeconfig: %v", err)
	}

	if len(config.Clusters) != 0 {
		t.Errorf("Expected 0 clusters in empty config, got %d", len(config.Clusters))
	}
	if len(config.Users) != 0 {
		t.Errorf("Expected 0 users in empty config, got %d", len(config.Users))
	}
}

func TestParseKubeConfig_MultipleClustersAndUsers(t *testing.T) {
	tmpDir := testutil.CreateTempCertDir(t)
	kubeConfigFile := filepath.Join(tmpDir, "kubeconfig")

	// Generate test certificates
	ca1 := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName: "ca1", Organization: "org1", Country: "US", Province: "CA", Days: 365, IsCA: true,
	})
	ca2 := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName: "ca2", Organization: "org2", Country: "US", Province: "CA", Days: 365, IsCA: true,
	})
	client1 := testutil.GenerateSignedCertificate(t, testutil.CertConfig{
		CommonName: "client1", Organization: "org", Country: "US", Province: "CA", Days: 365,
	}, ca1)
	client2 := testutil.GenerateSignedCertificate(t, testutil.CertConfig{
		CommonName: "client2", Organization: "org", Country: "US", Province: "CA", Days: 365,
	}, ca2)

	// Create kubeconfig with multiple clusters and users
	builder := testutil.NewKubeConfigBuilder()
	builder.AddClusterWithData("cluster1", "https://k8s1.example.com", string(ca1.CertPEM))
	builder.AddClusterWithData("cluster2", "https://k8s2.example.com", string(ca2.CertPEM))
	builder.AddUserWithData("user1", string(client1.CertPEM), string(client1.PrivateKeyPEM))
	builder.AddUserWithData("user2", string(client2.CertPEM), string(client2.PrivateKeyPEM))
	builder.Build(t, kubeConfigFile)

	// Parse the kubeconfig
	config, err := ParseKubeConfig(kubeConfigFile)
	if err != nil {
		t.Fatalf("Failed to parse kubeconfig: %v", err)
	}

	// Verify counts
	if len(config.Clusters) != 2 {
		t.Errorf("Expected 2 clusters, got %d", len(config.Clusters))
	}
	if len(config.Users) != 2 {
		t.Errorf("Expected 2 users, got %d", len(config.Users))
	}

	// Verify cluster names
	clusterNames := make(map[string]bool)
	for _, cluster := range config.Clusters {
		clusterNames[cluster.Name] = true
	}
	if !clusterNames["cluster1"] || !clusterNames["cluster2"] {
		t.Error("Expected to find both cluster1 and cluster2")
	}

	// Verify user names
	userNames := make(map[string]bool)
	for _, user := range config.Users {
		userNames[user.Name] = true
	}
	if !userNames["user1"] || !userNames["user2"] {
		t.Error("Expected to find both user1 and user2")
	}
}
