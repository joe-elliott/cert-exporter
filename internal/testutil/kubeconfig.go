package testutil

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v2"
)

// KubeConfigBuilder helps build kubeconfig files for testing
type KubeConfigBuilder struct {
	clusters []clusterEntry
	users    []userEntry
}

type clusterEntry struct {
	Name    string
	Cluster clusterConfig
}

type clusterConfig struct {
	Server                   string `yaml:"server"`
	CertificateAuthority     string `yaml:"certificate-authority,omitempty"`
	CertificateAuthorityData string `yaml:"certificate-authority-data,omitempty"`
}

type userEntry struct {
	Name string
	User userConfig
}

type userConfig struct {
	ClientCertificate     string `yaml:"client-certificate,omitempty"`
	ClientCertificateData string `yaml:"client-certificate-data,omitempty"`
	ClientKey             string `yaml:"client-key,omitempty"`
	ClientKeyData         string `yaml:"client-key-data,omitempty"`
}

type kubeConfig struct {
	Clusters []clusterEntry `yaml:"clusters"`
	Users    []userEntry    `yaml:"users"`
}

// NewKubeConfigBuilder creates a new kubeconfig builder
func NewKubeConfigBuilder() *KubeConfigBuilder {
	return &KubeConfigBuilder{}
}

// AddClusterWithFile adds a cluster with certificate from file
func (b *KubeConfigBuilder) AddClusterWithFile(name, server, certFile string) *KubeConfigBuilder {
	b.clusters = append(b.clusters, clusterEntry{
		Name: name,
		Cluster: clusterConfig{
			Server:               server,
			CertificateAuthority: certFile,
		},
	})
	return b
}

// AddClusterWithData adds a cluster with embedded certificate data
func (b *KubeConfigBuilder) AddClusterWithData(name, server, certData string) *KubeConfigBuilder {
	b.clusters = append(b.clusters, clusterEntry{
		Name: name,
		Cluster: clusterConfig{
			Server:                   server,
			CertificateAuthorityData: certData,
		},
	})
	return b
}

// AddUserWithFile adds a user with certificate and key from files
func (b *KubeConfigBuilder) AddUserWithFile(name, certFile, keyFile string) *KubeConfigBuilder {
	b.users = append(b.users, userEntry{
		Name: name,
		User: userConfig{
			ClientCertificate: certFile,
			ClientKey:         keyFile,
		},
	})
	return b
}

// AddUserWithData adds a user with embedded certificate and key data
func (b *KubeConfigBuilder) AddUserWithData(name, certData, keyData string) *KubeConfigBuilder {
	b.users = append(b.users, userEntry{
		Name: name,
		User: userConfig{
			ClientCertificateData: certData,
			ClientKeyData:         keyData,
		},
	})
	return b
}

// Build writes the kubeconfig to a file
func (b *KubeConfigBuilder) Build(t *testing.T, filename string) {
	t.Helper()

	config := kubeConfig{
		Clusters: b.clusters,
		Users:    b.users,
	}

	data, err := yaml.Marshal(config)
	if err != nil {
		t.Fatalf("Failed to marshal kubeconfig: %v", err)
	}

	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		t.Fatalf("Failed to write kubeconfig: %v", err)
	}
}
