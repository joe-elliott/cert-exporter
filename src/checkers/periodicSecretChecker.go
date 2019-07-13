package checkers

import (
	"time"

	clientset "github.com/joe-elliott/kubernetes-grafana-controller/pkg/client/clientset/versioned"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog"

	"github.com/golang/glog"
	"github.com/joe-elliott/cert-exporter/src/exporters"
)

// PeriodicSecretChecker is an object designed to check for files on disk at a regular interval
type PeriodicSecretChecker struct {
	period              time.Duration
	secretLabelSelector string
	kubeconfigPath      string
	exporter            exporters.Exporter
}

// NewSecretChecker is a factory method that returns a new PeriodicSecretChecker
func NewSecretChecker(period time.Duration, secretLabelSelector string, kubeconfigPath string, e exporters.Exporter) *PeriodicSecretChecker {
	return &PeriodicSecretChecker{
		period:              period,
		secretLabelSelector: secretLabelSelector,
		kubeconfigPath:      kubeconfigPath,
		exporter:            e,
	}
}

// StartChecking starts the periodic file check.  Most likely you want to run this as an independent go routine.
func (p *PeriodicSecretChecker) StartChecking() {

	config, err := clientcmd.BuildConfigFromFlags("", p.kubeconfigPath)
	if err != nil {
		glog.Fatalf("Error building kubeconfig: %s", err.Error())
	}

	// creates the clientset
	client, err := clientset.NewForConfig(config)
	if err != nil {
		glog.Fatalf("clientset.NewForConfig failed: %v", err)
	}

	periodChannel := time.Tick(p.period)

	for {
		glog.Info("Begin periodic check")

		secrets, err := client.CoreV1().Secrets("").List(v1.ListOptions{
			LabelSelector: p.secretLabelSelector,
		})

		if err != nil {
			glog.Errorf("Error requesting secrets %v", err)
			metrics.ErrorTotal.Inc()
		}

		for secret := range secrets {
			glog("%v", secrets)
		}

		<-periodChannel
	}
}
