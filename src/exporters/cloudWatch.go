package exporters

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatch"
)

// CloudWatch exporter
type CloudWatchExporter struct {
	region    string
	namespace string
}

func NewCloudWatchExporter(region, namespace string) *CloudWatchExporter {
	return &CloudWatchExporter{
		region:    region,
		namespace: namespace,
	}
}

// ExportMetrics exports metrics to CloudWatch
func (c *CloudWatchExporter) ExportMetrics(file, nodeName string) error {
	sess := session.Must(session.NewSession(&aws.Config{
		Region: aws.String(c.region),
	}))
	cw := cloudwatch.New(sess)

	metric, err := secondsToExpiryFromCertAsFile(file)
	if err != nil {
		return err
	}

	_, err = cw.PutMetricData(
		&cloudwatch.PutMetricDataInput{
			Namespace: aws.String(c.namespace),
			MetricData: []*cloudwatch.MetricDatum{
				&cloudwatch.MetricDatum{
					MetricName: aws.String(nodeName),
					Unit:       aws.String("Seconds"),
					Value:      aws.Float64(metric.durationUntilExpiry),
					Dimensions: []*cloudwatch.Dimension{
						&cloudwatch.Dimension{
							Name:  aws.String("CertExpiry"),
							Value: aws.String(metric.cn),
						},
					},
				},
				&cloudwatch.MetricDatum{
					MetricName: aws.String(nodeName),
					Unit:       aws.String("Seconds"),
					Value:      aws.Float64(metric.notAfter),
					Dimensions: []*cloudwatch.Dimension{
						&cloudwatch.Dimension{
							Name:  aws.String("CertNotAfter"),
							Value: aws.String(metric.cn),
						},
					},
				},
			},
		},
	)
	if err != nil {
		return err
	}

	return nil
}
