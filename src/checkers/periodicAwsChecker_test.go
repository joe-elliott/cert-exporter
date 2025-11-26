package checkers

import (
	"testing"
	"time"

	"github.com/joe-elliott/cert-exporter/src/exporters"
)

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
