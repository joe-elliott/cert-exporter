package checkers

import (
	"time"
	"path/filepath"

	"k8s.io/klog"
	"github.com/joe-elliott/cert-exporter/src/exporters"
	"github.com/joe-elliott/cert-exporter/src/metrics"
)

type PeriodicCertChecker struct {
	period time.Duration
	includeCertGlobs []string
	excludeCertGlobs []string
	exporter exporters.Exporter
}

func NewCertChecker(period time.Duration, includeCertGlobs []string, excludeCertGlobs []string, e exporters.Exporter) *PeriodicCertChecker {
	return &PeriodicCertChecker{
		period : period,
		includeCertGlobs : includeCertGlobs,
		excludeCertGlobs : excludeCertGlobs,
		exporter : e,
	}
}

func (p *PeriodicCertChecker) StartChecking() {

	periodChannel := time.Tick(p.period)

	for {
		klog.Info("Begin periodic check")

		for _, match := range p.getMatches() {

			if !p.includeFile(match) {
				continue
			}

			klog.Infof("Publishing metrics for %v", match)

			err := p.exporter.ExportMetrics(match)

			if err != nil {
				metrics.ErrorTotal.Inc()
				klog.Errorf("Error on %v: %v", match, err)
			}
		}

		<-periodChannel
	}
}

func (p *PeriodicCertChecker) getMatches() []string {
	ret := make([]string, 0)

	for _, includeGlob := range p.includeCertGlobs {

		matches, err := filepath.Glob(includeGlob)

		if err != nil {
			klog.Errorf("Glob failed on %v: %v", includeGlob, err)
			continue
		}

		ret = append(ret, matches...)
	}

	return ret
}

func (p *PeriodicCertChecker) includeFile(file string) bool {

	for _, excludeGlob := range p.excludeCertGlobs {
		exclude, err := filepath.Match(excludeGlob, file)

		if err != nil {
			klog.Errorf("Match failed on %v,%v: %v", excludeGlob, file, err)
			return false
		}

		if exclude {
			return false
		}
	}

	return true
}