package checkers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/secretsmanager/secretsmanageriface"

	"log/slog"

	"github.com/joe-elliott/cert-exporter/src/exporters"
	"github.com/joe-elliott/cert-exporter/src/metrics"
)

// SecretsManagerClientFactory creates a Secrets Manager client for testing
type SecretsManagerClientFactory func(region string) (secretsmanageriface.SecretsManagerAPI, error)

// PeriodicAwsChecker is an object designed to check for .pem files in AWS Secrets Manager
type PeriodicAwsChecker struct {
	awsAccount, awsRegion, awsKeySubString string
	awsSecrets                             []string
	awsIncludeFileInMetrics                bool
	period                                 time.Duration
	exporter                               *exporters.AwsExporter
	clientFactory                          SecretsManagerClientFactory
}

// defaultClientFactory creates a real AWS Secrets Manager client
func defaultClientFactory(region string) (secretsmanageriface.SecretsManagerAPI, error) {
	sess, err := session.NewSession()
	if err != nil {
		return nil, err
	}
	return secretsmanager.New(sess, aws.NewConfig().WithRegion(region)), nil
}

// NewCertChecker is a factory method that returns a new AwsCertChecker
func NewAwsChecker(awsAccount, awsRegion, awsKeySubString string, awsSecrets []string, awsIncludeFileInMetrics bool, period time.Duration, e *exporters.AwsExporter) *PeriodicAwsChecker {
	return NewAwsCheckerWithClientFactory(awsAccount, awsRegion, awsKeySubString, awsSecrets, awsIncludeFileInMetrics, period, e, defaultClientFactory)
}

// NewAwsCheckerWithClientFactory creates a checker with a custom client factory for testing
func NewAwsCheckerWithClientFactory(awsAccount, awsRegion, awsKeySubString string, awsSecrets []string, awsIncludeFileInMetrics bool, period time.Duration, e *exporters.AwsExporter, clientFactory SecretsManagerClientFactory) *PeriodicAwsChecker {
	return &PeriodicAwsChecker{
		awsAccount:              awsAccount,
		awsRegion:               awsRegion,
		awsKeySubString:         awsKeySubString,
		awsSecrets:              awsSecrets,
		awsIncludeFileInMetrics: awsIncludeFileInMetrics,
		period:                  period,
		exporter:                e,
		clientFactory:           clientFactory,
	}
}

// StartChecking starts the periodic file check.  Most likely you want to run this as an independent go routine.
func (p *PeriodicAwsChecker) StartChecking() {
	periodChannel := time.Tick(p.period)
	for {
		slog.Info("AWS Checker: Begin periodic check")
		p.exporter.ResetMetrics()

		if err := p.checkSecrets(); err != nil {
			slog.Error("Error checking secrets", "error", err)
			metrics.ErrorTotal.Inc()
		}

		<-periodChannel
	}
}

// checkSecrets performs one round of secret checking - extracted for testability
func (p *PeriodicAwsChecker) checkSecrets() error {
	// Create AWS client
	client, err := p.clientFactory(p.awsRegion)
	if err != nil {
		slog.Error("Error initializing AWS client", "error", err)
		metrics.ErrorTotal.Inc()
		return err
	}

	// Process each secret
	for _, secretName := range p.awsSecrets {
		if err := p.processSecret(client, secretName); err != nil {
			slog.Error("Error processing secret", "secret", secretName, "error", err)
			metrics.ErrorTotal.Inc()
			// Continue processing other secrets
		}
	}

	return nil
}

// processSecret retrieves and processes a single secret - extracted for testability
func (p *PeriodicAwsChecker) processSecret(client secretsmanageriface.SecretsManagerAPI, secretName string) error {
	slog.Info("Getting secret " + secretName + " from AWS Secrets Manager")

	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String("arn:aws:secretsmanager:" + p.awsRegion + ":" + p.awsAccount + ":secret:" + secretName),
	}

	secretValue, err := client.GetSecretValue(input)
	if err != nil {
		return err
	}

	if secretValue.SecretString == nil {
		slog.Info("Secret has no string value", "secret", secretName)
		return nil
	}

	secretString := *secretValue.SecretString

	var secretMap map[string]interface{}
	if err := json.Unmarshal([]byte(secretString), &secretMap); err != nil {
		return err
	}

	// Process each key in the secret
	for key, value := range secretMap {
		if strings.Contains(key, p.awsKeySubString) {
			if err := p.processCertificateKey(secretName, key, value); err != nil {
				slog.Error("Error processing certificate key", "key", key, "secret", secretName, "error", err)
				metrics.ErrorTotal.Inc()
				// Continue processing other keys
			}
		}
	}

	return nil
}

// processCertificateKey processes a single certificate key from a secret - extracted for testability
func (p *PeriodicAwsChecker) processCertificateKey(secretName, key string, value interface{}) error {
	stringValue, ok := value.(string)
	if !ok {
		return nil // Skip non-string values
	}

	// Handle two formats: base64-encoded or raw PEM
	if strings.HasPrefix(stringValue, "-----BEGIN CERTIFICATE-----") {
		// Raw PEM format - need to base64 encode for the exporter
		stringValue = base64.StdEncoding.EncodeToString([]byte(stringValue))
	}

	slog.Info("Exporting metrics from key", "key", key)
	return p.exporter.ExportMetrics(stringValue, secretName, key, p.awsIncludeFileInMetrics)
}
