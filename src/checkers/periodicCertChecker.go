package checkers

import (
	"time"

	"github.com/golang/glog"

	"github.com/bmatcuk/doublestar/v3"
	"github.com/hakhundov/cert-exporter/src/exporters"
	"github.com/hakhundov/cert-exporter/src/metrics"
)

// PeriodicCertChecker is an object designed to check for files on disk at a regular interval
type PeriodicCertChecker struct {
	period           time.Duration
	includeCertGlobs []string
	excludeCertGlobs []string
	nodeName         string
	exporter         exporters.Exporter
}

// NewCertChecker is a factory method that returns a new PeriodicCertChecker
func NewCertChecker(period time.Duration, includeCertGlobs, excludeCertGlobs []string, nodeName string, e exporters.Exporter) *PeriodicCertChecker {
	return &PeriodicCertChecker{
		period:           period,
		includeCertGlobs: includeCertGlobs,
		excludeCertGlobs: excludeCertGlobs,
		nodeName:         nodeName,
		exporter:         e,
	}
}

// StartChecking starts the periodic file check.  Most likely you want to run this as an independent go routine.
func (p *PeriodicCertChecker) StartChecking() {
	periodChannel := time.Tick(p.period)

	for {
		glog.Info("Begin periodic check")
		for _, match := range p.getMatches() {
			glog.Infof("Publishing %v node metrics %v", p.nodeName, match)

			err := p.exporter.ExportMetrics(match, p.nodeName)
			if err != nil {
				metrics.ErrorTotal.Inc()
				glog.Errorf("Error on %v: %v", match, err)
			}
		}

		<-periodChannel
	}
}

func (p *PeriodicCertChecker) getMatches() []string {
	set := map[string]bool{}
	for _, includeGlob := range p.includeCertGlobs {
		matches, err := doublestar.Glob(includeGlob)
		if err != nil {
			metrics.ErrorTotal.Inc()
			glog.Errorf("Glob failed on %v: %v", includeGlob, err)
			continue
		}
		for _, match := range matches {
			set[match] = true
		}
	}

	for _, excludeGlob := range p.excludeCertGlobs {
		matches, err := doublestar.Glob(excludeGlob)
		if err != nil {
			metrics.ErrorTotal.Inc()
			glog.Errorf("Glob failed on %v: %v", excludeGlob, err)
			continue
		}
		for _, match := range matches {
			delete(set, match)
		}
	}

	res := make([]string, len(set))
	i := 0
	for k := range set {
		res[i] = k
		i++
	}
	return res
}