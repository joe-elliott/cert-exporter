package checkers

import (
	"fmt"
	"path/filepath"
	"time"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/golang/glog"
	"github.com/joe-elliott/cert-exporter/src/exporters"
	"github.com/joe-elliott/cert-exporter/src/metrics"
)

// PeriodicSecretChecker is an object designed to check for files on disk at a regular interval
type PeriodicSecretChecker struct {
	period          time.Duration
	labelSelectors  []string
	secretsDataGlob string
	kubeconfigPath  string
	exporter        exporters.Exporter
}

// NewSecretChecker is a factory method that returns a new PeriodicSecretChecker
func NewSecretChecker(period time.Duration, labelSelectors []string, secretsDataGlob string, kubeconfigPath string, e exporters.Exporter) *PeriodicSecretChecker {
	return &PeriodicSecretChecker{
		period:          period,
		labelSelectors:  labelSelectors,
		secretsDataGlob: secretsDataGlob,
		kubeconfigPath:  kubeconfigPath,
		exporter:        e,
	}
}

// StartChecking starts the periodic file check.  Most likely you want to run this as an independent go routine.
func (p *PeriodicSecretChecker) StartChecking() {

	config, err := clientcmd.BuildConfigFromFlags("", p.kubeconfigPath)
	if err != nil {
		glog.Fatalf("Error building kubeconfig: %s", err.Error())
	}

	// creates the clientset
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		glog.Fatalf("kubernetes.NewForConfig failed: %v", err)
	}

	periodChannel := time.Tick(p.period)

	for {
		glog.Info("Begin periodic check")

		for _, labelSelector := range p.labelSelectors {

			secrets, err := client.CoreV1().Secrets("").List(v1.ListOptions{
				LabelSelector: labelSelector,
			})

			if err != nil {
				glog.Errorf("Error requesting secrets %v", err)
				metrics.ErrorTotal.Inc()
				continue
			}

			for _, secret := range secrets.Items {

				for name, _ := range secret.Data {

					include, _ := filepath.Match(p.secretsDataGlob, name)

					if include {
						fmt.Println(secret.Name, name)
					}
				}
			}
		}

		<-periodChannel
	}
}
