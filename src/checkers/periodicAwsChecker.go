package checkers

import (
	"time"
	"fmt"
	"encoding/json"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"

	"github.com/golang/glog"

	"github.com/hakhundov/cert-exporter/src/exporters"
	"github.com/hakhundov/cert-exporter/src/metrics"
)

// PeriodicAwsChecker is an object designed to check for .pem files in AWS Secrets Manager
type PeriodicAwsChecker struct {
	awsAccount, awsRegion string
	period           time.Duration
	exporter         *exporters.AwsExporter
}

// NewCertChecker is a factory method that returns a new AwsCertChecker
func NewAwsChecker(awsAccount string, awsRegion string, period time.Duration, e *exporters.AwsExporter) *PeriodicAwsChecker {
	return &PeriodicAwsChecker{
		awsAccount:	      awsAccount,
		awsRegion:		  awsRegion,
		period:           period,
		exporter:         e,
	}
}

// StartChecking starts the periodic file check.  Most likely you want to run this as an independent go routine.
func (p *PeriodicAwsChecker) StartChecking() {
	periodChannel := time.Tick(p.period)

	for {
		glog.Info("Begin periodic check")

		// Create a Session with a custom region
		svc := secretsmanager.New(session.New(), aws.NewConfig().WithRegion(p.awsRegion))

		//TODO: Incorporate below block in FOR loop over all secrets passed as environment variable
		secretNameArray := []string{"mnyp-secrets-auth/acc/namespace","mnyp-secrets-auth/acc/am_config","mnyp-secrets-auth/acc/am_encap"}
		//account:="689483148385"
		//region:="eu-central-1"

		for _, secretName := range secretNameArray {
			fmt.Println("# [INFO] Getting secret "+secretName+" from AWS Secrets Manager")


			input := &secretsmanager.GetSecretValueInput{
				SecretId:     aws.String("arn:aws:secretsmanager:"+p.awsRegion+":"+p.awsAccount+":secret:"+secretName),
			}
			
			secretValue, err := svc.GetSecretValue(input)
			
			if (err != nil){
				metrics.ErrorTotal.Inc()
				glog.Error(err)
			}
	
			secretString:=*secretValue.SecretString
	
			var secretMap map[string]interface{}
			json.Unmarshal([]byte(secretString), &secretMap)
	
			for key, value := range secretMap {
				if (strings.Contains(key, ".pem")){
					fmt.Println("# [INFO] Exporting metrics from ", key)
					err := p.exporter.ExportMetrics(value.(string),secretName)
					if err != nil {
						metrics.ErrorTotal.Inc()
						fmt.Errorf("Error exporting certificate metrics")
					}
				}
			}
		}

		<-periodChannel
	}
}
