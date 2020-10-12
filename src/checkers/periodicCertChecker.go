package checkers

import (
	"path/filepath"
	"time"

	"github.com/golang/glog"

	"github.com/joe-elliott/cert-exporter/src/exporters"
	"github.com/joe-elliott/cert-exporter/src/metrics"
)

// PeriodicCertChecker is an object designed to check for files on disk at a regular interval
type PeriodicCertChecker struct {
	period               time.Duration
	includeCertGlobs     []string
	excludeCertGlobs     []string
	nodeName             string
	includeFullCertChain bool
	exporter             exporters.Exporter
}

// NewCertChecker is a factory method that returns a new PeriodicCertChecker
func NewCertChecker(period time.Duration, includeCertGlobs, excludeCertGlobs []string, nodeName string, includeFullCertChain bool, e exporters.Exporter) *PeriodicCertChecker {
	return &PeriodicCertChecker{
		period:               period,
		includeCertGlobs:     includeCertGlobs,
		excludeCertGlobs:     excludeCertGlobs,
		nodeName:             nodeName,
		includeFullCertChain: includeFullCertChain,
		exporter:             e,
	}
}

// StartChecking starts the periodic file check.  Most likely you want to run this as an independent go routine.
func (p *PeriodicCertChecker) StartChecking() {
	periodChannel := time.Tick(p.period)

	for {
		glog.Info("Begin periodic check")
		for _, match := range p.getMatches() {
			if !p.includeFile(match) {
				continue
			}

			glog.Infof("Publishing %v node metrics %v", p.nodeName, match)

			err := p.exporter.ExportMetrics(match, p.nodeName, p.includeFullCertChain)
			if err != nil {
				metrics.ErrorTotal.Inc()
				glog.Errorf("Error on %v: %v", match, err)
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
			metrics.ErrorTotal.Inc()
			glog.Errorf("Glob failed on %v: %v", includeGlob, err)
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
			metrics.ErrorTotal.Inc()
			glog.Errorf("Match failed on %v,%v: %v", excludeGlob, file, err)
			return false
		}

		if exclude {
			return false
		}
	}

	return true
}
