package checkers

import (
	"time"

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

	periodChannel := time.Tick(p.period)

	for {
		glog.Info("Begin periodic check")

		<-periodChannel
	}
}
