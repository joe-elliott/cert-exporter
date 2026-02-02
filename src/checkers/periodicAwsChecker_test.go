package checkers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/secretsmanager/secretsmanageriface"
	"github.com/joe-elliott/cert-exporter/internal/testutil"
	"github.com/joe-elliott/cert-exporter/src/exporters"
	"github.com/joe-elliott/cert-exporter/src/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

// mockSecretsManagerClient implements secretsmanageriface.SecretsManagerAPI for testing
type mockSecretsManagerClient struct {
	secretsmanageriface.SecretsManagerAPI
	secrets map[string]string
	err     error
}

func (m *mockSecretsManagerClient) GetSecretValue(input *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
	if m.err != nil {
		return nil, m.err
	}

	secretName := *input.SecretId
	if value, ok := m.secrets[secretName]; ok {
		return &secretsmanager.GetSecretValueOutput{
			SecretString: aws.String(value),
		}, nil
	}

	return nil, errors.New("secret not found")
}

func TestNewAwsChecker(t *testing.T) {
	awsAccount := "123456789012"
	awsRegion := "us-east-1"
	awsKeySubString := "certificate"
	awsSecrets := []string{"secret1", "secret2"}
	period := 5 * time.Minute
	exporter := &exporters.AwsExporter{}

	checker := NewAwsChecker(awsAccount, awsRegion, awsKeySubString, awsSecrets, period, exporter)

	if checker == nil {
		t.Fatal("Expected NewAwsChecker to return non-nil checker")
	}

	if checker.awsAccount != awsAccount {
		t.Errorf("Expected awsAccount '%s', got '%s'", awsAccount, checker.awsAccount)
	}

	if checker.awsRegion != awsRegion {
		t.Errorf("Expected awsRegion '%s', got '%s'", awsRegion, checker.awsRegion)
	}

	if checker.awsKeySubString != awsKeySubString {
		t.Errorf("Expected awsKeySubString '%s', got '%s'", awsKeySubString, checker.awsKeySubString)
	}

	if len(checker.awsSecrets) != len(awsSecrets) {
		t.Errorf("Expected %d awsSecrets, got %d", len(awsSecrets), len(checker.awsSecrets))
	}

	for i, secret := range awsSecrets {
		if checker.awsSecrets[i] != secret {
			t.Errorf("Expected awsSecret[%d] = '%s', got '%s'", i, secret, checker.awsSecrets[i])
		}
	}

	if checker.period != period {
		t.Errorf("Expected period %v, got %v", period, checker.period)
	}

	if checker.exporter != exporter {
		t.Error("Expected exporter to match provided exporter")
	}

	if checker.clientFactory == nil {
		t.Error("Expected clientFactory to be set")
	}
}

func TestNewAwsChecker_EmptySecrets(t *testing.T) {
	checker := NewAwsChecker("account", "region", "key", []string{}, time.Second, nil)

	if checker == nil {
		t.Fatal("Expected NewAwsChecker to return non-nil checker")
	}

	if len(checker.awsSecrets) != 0 {
		t.Error("Expected empty awsSecrets")
	}
}

func TestNewAwsChecker_MultipleSecrets(t *testing.T) {
	secrets := []string{"secret1", "secret2", "secret3", "secret4"}
	checker := NewAwsChecker("123", "us-west-2", "cert", secrets, 10*time.Minute, &exporters.AwsExporter{})

	if len(checker.awsSecrets) != len(secrets) {
		t.Errorf("Expected %d secrets, got %d", len(secrets), len(checker.awsSecrets))
	}
}

func TestPeriodicAwsChecker_ProcessSecret_Success(t *testing.T) {
	testRegistry := prometheus.NewRegistry()
	metrics.Init(true, testRegistry)

	// Generate test certificate
	cert := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName:   "test-aws-cert",
		Organization: "test-org",
		Country:      "US",
		Province:     "CA",
		Days:         30,
		IsCA:         false,
	})

	// Create secret with certificate
	secretData := map[string]interface{}{
		"certificate.pem": base64.StdEncoding.EncodeToString(cert.CertPEM),
		"other-key":       "not-a-cert",
	}
	secretJSON, _ := json.Marshal(secretData)

	mockClient := &mockSecretsManagerClient{
		secrets: map[string]string{
			"arn:aws:secretsmanager:us-east-1:123456789012:secret:test-secret": string(secretJSON),
		},
	}

	exporter := &exporters.AwsExporter{}
	checker := NewAwsCheckerWithClientFactory(
		"123456789012",
		"us-east-1",
		".pem",
		[]string{"test-secret"},
		time.Hour,
		exporter,
		func(region string) (secretsmanageriface.SecretsManagerAPI, error) {
			return mockClient, nil
		},
	)

	// Process the secret
	err := checker.processSecret(mockClient, "test-secret")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify metrics were created
	mfs, err := testRegistry.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	found := false
	for _, mf := range mfs {
		if mf.GetName() == "cert_exporter_cert_expires_in_seconds_aws" {
			for _, metric := range mf.GetMetric() {
				labels := make(map[string]string)
				for _, label := range metric.GetLabel() {
					labels[label.GetName()] = label.GetValue()
				}
				if labels["secretName"] == "test-secret" && labels["cn"] == "test-aws-cert" {
					found = true
					break
				}
			}
		}
	}

	if !found {
		t.Error("Expected to find AWS certificate metric")
	}
}

func TestPeriodicAwsChecker_ProcessSecret_RawPEM(t *testing.T) {
	testRegistry := prometheus.NewRegistry()
	metrics.Init(true, testRegistry)

	// Generate test certificate
	cert := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName: "raw-pem-cert", Organization: "org", Country: "US", Province: "CA", Days: 30,
	})

	// Create secret with RAW PEM (not base64 encoded)
	secretData := map[string]interface{}{
		"certificate.pem": string(cert.CertPEM), // Raw PEM string
	}
	secretJSON, _ := json.Marshal(secretData)

	mockClient := &mockSecretsManagerClient{
		secrets: map[string]string{
			"arn:aws:secretsmanager:us-east-1:123456789012:secret:raw-secret": string(secretJSON),
		},
	}

	exporter := &exporters.AwsExporter{}
	checker := NewAwsCheckerWithClientFactory(
		"123456789012",
		"us-east-1",
		".pem",
		[]string{"raw-secret"},
		time.Hour,
		exporter,
		func(region string) (secretsmanageriface.SecretsManagerAPI, error) {
			return mockClient, nil
		},
	)

	// Process the secret
	err := checker.processSecret(mockClient, "raw-secret")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify metrics were created
	mfs, err := testRegistry.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	found := false
	for _, mf := range mfs {
		if mf.GetName() == "cert_exporter_cert_expires_in_seconds_aws" {
			for _, metric := range mf.GetMetric() {
				labels := make(map[string]string)
				for _, label := range metric.GetLabel() {
					labels[label.GetName()] = label.GetValue()
				}
				if labels["secretName"] == "raw-secret" && labels["cn"] == "raw-pem-cert" {
					found = true
					break
				}
			}
		}
	}

	if !found {
		t.Error("Expected to find AWS certificate metric for raw PEM")
	}
}

func TestPeriodicAwsChecker_ProcessSecret_KeyFiltering(t *testing.T) {
	testRegistry := prometheus.NewRegistry()
	metrics.Init(true, testRegistry)

	// Generate test certificate
	cert := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName: "filtered-cert", Organization: "org", Country: "US", Province: "CA", Days: 30,
	})

	// Create secret with multiple keys, only some matching the filter
	secretData := map[string]interface{}{
		"certificate.pem": base64.StdEncoding.EncodeToString(cert.CertPEM),
		"ca-cert.pem":     base64.StdEncoding.EncodeToString(cert.CertPEM),
		"private-key":     "not-matched",
		"config.json":     "also-not-matched",
	}
	secretJSON, _ := json.Marshal(secretData)

	mockClient := &mockSecretsManagerClient{
		secrets: map[string]string{
			"arn:aws:secretsmanager:us-east-1:123456789012:secret:filter-test": string(secretJSON),
		},
	}

	exporter := &exporters.AwsExporter{}
	checker := NewAwsCheckerWithClientFactory(
		"123456789012",
		"us-east-1",
		".pem", // Only match keys containing .pem
		[]string{"filter-test"},
		time.Hour,
		exporter,
		func(region string) (secretsmanageriface.SecretsManagerAPI, error) {
			return mockClient, nil
		},
	)

	err := checker.processSecret(mockClient, "filter-test")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify only .pem keys were processed
	mfs, err := testRegistry.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	pemKeyCount := 0
	for _, mf := range mfs {
		if mf.GetName() == "cert_exporter_cert_expires_in_seconds_aws" {
			for _, metric := range mf.GetMetric() {
				labels := make(map[string]string)
				for _, label := range metric.GetLabel() {
					labels[label.GetName()] = label.GetValue()
				}
				if labels["secretName"] == "filter-test" {
					key := labels["key"]
					// Should only match keys containing .pem
					if key == "certificate.pem" || key == "ca-cert.pem" {
						pemKeyCount++
					} else {
						t.Errorf("Unexpected key processed: %s", key)
					}
				}
			}
		}
	}

	if pemKeyCount != 2 {
		t.Errorf("Expected 2 .pem keys to be processed, got %d", pemKeyCount)
	}
}

func TestPeriodicAwsChecker_ProcessSecret_ClientError(t *testing.T) {
	mockClient := &mockSecretsManagerClient{
		err: errors.New("AWS API error"),
	}

	exporter := &exporters.AwsExporter{}
	checker := NewAwsCheckerWithClientFactory(
		"123456789012",
		"us-east-1",
		".pem",
		[]string{"error-secret"},
		time.Hour,
		exporter,
		func(region string) (secretsmanageriface.SecretsManagerAPI, error) {
			return mockClient, nil
		},
	)

	err := checker.processSecret(mockClient, "error-secret")
	if err == nil {
		t.Error("Expected error when client returns error")
	}
}

func TestPeriodicAwsChecker_ProcessSecret_InvalidJSON(t *testing.T) {
	mockClient := &mockSecretsManagerClient{
		secrets: map[string]string{
			"arn:aws:secretsmanager:us-east-1:123456789012:secret:bad-json": "not valid json{",
		},
	}

	exporter := &exporters.AwsExporter{}
	checker := NewAwsCheckerWithClientFactory(
		"123456789012",
		"us-east-1",
		".pem",
		[]string{"bad-json"},
		time.Hour,
		exporter,
		func(region string) (secretsmanageriface.SecretsManagerAPI, error) {
			return mockClient, nil
		},
	)

	err := checker.processSecret(mockClient, "bad-json")
	if err == nil {
		t.Error("Expected error when secret contains invalid JSON")
	}
}

func TestPeriodicAwsChecker_CheckSecrets_MultipleSecrets(t *testing.T) {
	testRegistry := prometheus.NewRegistry()
	metrics.Init(true, testRegistry)

	// Generate test certificates
	cert1 := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName: "cert-1", Organization: "org", Country: "US", Province: "CA", Days: 30,
	})
	cert2 := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName: "cert-2", Organization: "org", Country: "US", Province: "CA", Days: 60,
	})

	// Create multiple secrets
	secret1Data := map[string]interface{}{
		"cert.pem": base64.StdEncoding.EncodeToString(cert1.CertPEM),
	}
	secret1JSON, _ := json.Marshal(secret1Data)

	secret2Data := map[string]interface{}{
		"cert.pem": base64.StdEncoding.EncodeToString(cert2.CertPEM),
	}
	secret2JSON, _ := json.Marshal(secret2Data)

	mockClient := &mockSecretsManagerClient{
		secrets: map[string]string{
			"arn:aws:secretsmanager:us-east-1:123456789012:secret:secret-1": string(secret1JSON),
			"arn:aws:secretsmanager:us-east-1:123456789012:secret:secret-2": string(secret2JSON),
		},
	}

	exporter := &exporters.AwsExporter{}
	checker := NewAwsCheckerWithClientFactory(
		"123456789012",
		"us-east-1",
		".pem",
		[]string{"secret-1", "secret-2"},
		time.Hour,
		exporter,
		func(region string) (secretsmanageriface.SecretsManagerAPI, error) {
			return mockClient, nil
		},
	)

	err := checker.checkSecrets()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify metrics for both secrets
	mfs, err := testRegistry.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	foundSecrets := make(map[string]bool)
	for _, mf := range mfs {
		if mf.GetName() == "cert_exporter_cert_expires_in_seconds_aws" {
			for _, metric := range mf.GetMetric() {
				labels := make(map[string]string)
				for _, label := range metric.GetLabel() {
					labels[label.GetName()] = label.GetValue()
				}
				foundSecrets[labels["secretName"]] = true
			}
		}
	}

	if !foundSecrets["secret-1"] {
		t.Error("Expected to find metric for secret-1")
	}
	if !foundSecrets["secret-2"] {
		t.Error("Expected to find metric for secret-2")
	}
}

func TestPeriodicAwsChecker_CheckSecrets_ClientFactoryError(t *testing.T) {
	exporter := &exporters.AwsExporter{}
	checker := NewAwsCheckerWithClientFactory(
		"123456789012",
		"us-east-1",
		".pem",
		[]string{"test-secret"},
		time.Hour,
		exporter,
		func(region string) (secretsmanageriface.SecretsManagerAPI, error) {
			return nil, errors.New("failed to create client")
		},
	)

	err := checker.checkSecrets()
	if err == nil {
		t.Error("Expected error when client factory fails")
	}
}
