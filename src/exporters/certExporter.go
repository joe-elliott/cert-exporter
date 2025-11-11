package exporters

import (
	"github.com/joe-elliott/cert-exporter/src/args"
	"github.com/joe-elliott/cert-exporter/src/metrics"
)

// CertExporter exports PEM file certs
type CertExporter struct {
	PasswordSpecs      []args.PasswordSpec
	DefaultPassword    string
	ExcludeCNGlobs     args.GlobArgs
	ExcludeAliasGlobs  args.GlobArgs
	ExcludeIssuerGlobs args.GlobArgs
}

// NewCertExporter creates a new CertExporter with an optional password.
func NewCertExporter(specs []args.PasswordSpec, defaultPassword string, excludeCNGlobs args.GlobArgs, excludeAliasGlobs args.GlobArgs, excludeIssuerGlobs args.GlobArgs) *CertExporter {
	return &CertExporter{
		PasswordSpecs:      specs,
		DefaultPassword:    defaultPassword,
		ExcludeCNGlobs:     excludeCNGlobs,
		ExcludeAliasGlobs:  excludeAliasGlobs,
		ExcludeIssuerGlobs: excludeIssuerGlobs,
	}
}

// ExportMetrics exports the provided PEM file
func (c *CertExporter) ExportMetrics(file, nodeName string) error {
	resolvedPassword := GetPasswordForFile(file, c.PasswordSpecs, c.DefaultPassword)
	metricCollection, err := secondsToExpiryFromCertAsFile(file, resolvedPassword, c.ExcludeCNGlobs, c.ExcludeAliasGlobs, c.ExcludeIssuerGlobs)
	if err != nil {
		return err
	}

	for _, metric := range metricCollection {
		metrics.CertExpirySeconds.WithLabelValues(file, metric.issuer, metric.cn, nodeName, metric.Alias).Set(metric.durationUntilExpiry)
		metrics.CertNotAfterTimestamp.WithLabelValues(file, metric.issuer, metric.cn, nodeName, metric.Alias).Set(metric.notAfter)
		metrics.CertNotBeforeTimestamp.WithLabelValues(file, metric.issuer, metric.cn, nodeName, metric.Alias).Set(metric.notBefore)
	}

	return nil
}

func (c *CertExporter) ResetMetrics() {
	metrics.CertExpirySeconds.Reset()
	metrics.CertNotAfterTimestamp.Reset()
	metrics.CertNotBeforeTimestamp.Reset()
}
