package exporters

import (
	"fmt"
	"path"

	"github.com/joe-elliott/cert-exporter/src/kubeconfig"
	"github.com/joe-elliott/cert-exporter/src/metrics"
)

// KubeConfigExporter exports kubeconfig certs
type KubeConfigExporter struct {
	ExcludeCNGlobs     []string
	ExcludeIssuerGlobs []string
}

// ExportMetrics exports all certs in the passed in kubeconfig file
func (c *KubeConfigExporter) ExportMetrics(file, nodeName string) error {
	k, err := kubeconfig.ParseKubeConfig(file)

	if err != nil {
		return err
	}

	for _, cluster := range k.Clusters {
		var metricCollection []certMetric

		if cluster.Cluster.CertificateAuthorityData != "" {
			metricCollection, err = secondsToExpiryFromCertAsBase64String(cluster.Cluster.CertificateAuthorityData)

			if err != nil {
				return err
			}
		} else if cluster.Cluster.CertificateAuthority != "" {
			certFile := pathToFileFromKubeConfig(cluster.Cluster.CertificateAuthority, file)
			metricCollection, err = secondsToExpiryFromCertAsFile(certFile)

			if err != nil {
				return err
			}
		} else {
			return fmt.Errorf("Cluster %v does not have CertAuthority or CertAuthorityData", cluster.Name)
		}

		metricCollection = filterMetrics(metricCollection, c.ExcludeCNGlobs, c.ExcludeIssuerGlobs)

		for _, metric := range metricCollection {
			labels := metrics.AppendSerial([]string{file, "cluster", metric.cn, metric.issuer, cluster.Name, nodeName}, metric.serial)
			metrics.KubeConfigExpirySeconds.WithLabelValues(labels...).Set(metric.durationUntilExpiry)
			metrics.KubeConfigNotAfterTimestamp.WithLabelValues(labels...).Set(metric.notAfter)
			metrics.KubeConfigNotBeforeTimestamp.WithLabelValues(labels...).Set(metric.notBefore)
		}
	}

	for _, user := range k.Users {
		var metricCollection []certMetric

		if user.User.ClientCertificateData != "" {
			metricCollection, err = secondsToExpiryFromCertAsBase64String(user.User.ClientCertificateData)

			if err != nil {
				return err
			}
		} else if user.User.ClientCertificate != "" {
			certFile := pathToFileFromKubeConfig(user.User.ClientCertificate, file)
			metricCollection, err = secondsToExpiryFromCertAsFile(certFile)

			if err != nil {
				return err
			}
		} else {
			return fmt.Errorf("User %v does not have ClientCert or ClientCertData", user.Name)
		}

		metricCollection = filterMetrics(metricCollection, c.ExcludeCNGlobs, c.ExcludeIssuerGlobs)

		for _, metric := range metricCollection {
			labels := metrics.AppendSerial([]string{file, "user", metric.cn, metric.issuer, user.Name, nodeName}, metric.serial)
			metrics.KubeConfigExpirySeconds.WithLabelValues(labels...).Set(metric.durationUntilExpiry)
			metrics.KubeConfigNotAfterTimestamp.WithLabelValues(labels...).Set(metric.notAfter)
			metrics.KubeConfigNotBeforeTimestamp.WithLabelValues(labels...).Set(metric.notBefore)
		}
	}

	return nil
}

func pathToFileFromKubeConfig(file, kubeConfigFile string) string {
	if !path.IsAbs(file) {
		kubeConfigPath := path.Dir(kubeConfigFile)
		file = path.Join(kubeConfigPath, file)
	}

	return file
}

func (c *KubeConfigExporter) ResetMetrics() {
	metrics.KubeConfigExpirySeconds.Reset()
	metrics.KubeConfigNotAfterTimestamp.Reset()
	metrics.KubeConfigNotBeforeTimestamp.Reset()
}
