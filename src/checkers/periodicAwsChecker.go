package checkers

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"

	"github.com/golang/glog"

	"github.com/joe-elliott/cert-exporter/src/exporters"
	"github.com/joe-elliott/cert-exporter/src/metrics"
)

// PeriodicAwsChecker is an object designed to check for .pem files in AWS Secrets Manager
type PeriodicAwsChecker struct {
	awsAccount, awsRegion, awsKeySubString string
	awsSecrets                             []string
	period                                 time.Duration
	exporter                               *exporters.AwsExporter
}

// NewCertChecker is a factory method that returns a new AwsCertChecker
func NewAwsChecker(awsAccount, awsRegion, awsKeySubString string, awsSecrets []string, period time.Duration, e *exporters.AwsExporter) *PeriodicAwsChecker {
	return &PeriodicAwsChecker{
		awsAccount:      awsAccount,
		awsRegion:       awsRegion,
		awsKeySubString: awsKeySubString,
		awsSecrets:      awsSecrets,
		period:          period,
		exporter:        e,
	}
}

// StartChecking starts the periodic file check.  Most likely you want to run this as an independent go routine.
func (p *PeriodicAwsChecker) StartChecking() {
	periodChannel := time.Tick(p.period)
	for {
		glog.Info("AWS Checker: Begin periodic check")

		p.exporter.ResetMetrics()

		// Create a Session with a custom region
		session, err := session.NewSession()

		if err != nil {
			glog.Error("Error initializing AWS session: ", err)
			metrics.ErrorTotal.Inc()
			continue
		}

		svc := secretsmanager.New(session, aws.NewConfig().WithRegion(p.awsRegion))

		for _, secretName := range p.awsSecrets {
			glog.Info("Getting secret " + secretName + " from AWS Secrets Manager")

			input := &secretsmanager.GetSecretValueInput{
				SecretId: aws.String("arn:aws:secretsmanager:" + p.awsRegion + ":" + p.awsAccount + ":secret:" + secretName),
			}

			secretValue, err := svc.GetSecretValue(input)

			if err != nil {
				glog.Error("Error in GetSecretValue: ", err)
				metrics.ErrorTotal.Inc()
				continue
			}

			secretString := *secretValue.SecretString

			var secretMap map[string]interface{}
			json.Unmarshal([]byte(secretString), &secretMap)

			for key, value := range secretMap {
				if strings.Contains(key, p.awsKeySubString) {
					stringValue := value.(string)

					if strings.HasPrefix(stringValue, "-----BEGIN CERTIFICATE-----") {
						// There are 2 ways to store a certificate in aws, base64 encoded or on a single
						// line. As the 'ExportMetrics' does the decoding, adding this check would make
						// it the easiest change without changing a lot of other code.
						stringValue = base64.StdEncoding.EncodeToString([]byte(stringValue))
					}

					glog.Info("Exporting metrics from ", key)
					err := p.exporter.ExportMetrics(stringValue, secretName, key)
					if err != nil {
						metrics.ErrorTotal.Inc()
						glog.Error("Error exporting certificate metrics")
					}
				}
			}
		}

		<-periodChannel
	}
}
