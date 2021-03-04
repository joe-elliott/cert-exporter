package exporters

import (
	"fmt"
	"path"

	"github.com/hakhundov/cert-exporter/src/kubeconfig"
	"github.com/hakhundov/cert-exporter/src/metrics"
)

// KubeConfigExporter exports kubeconfig certs
type KubeConfigExporter struct {
}

// ExportMetrics exports all certs in the passed in kubeconfig file
func (c *KubeConfigExporter) ExportMetrics(file, nodeName string) error {
	k, err := kubeconfig.ParseKubeConfig(file)

	if err != nil {
		return err
	}

	for _, c := range k.Clusters {
		var metricCollection []certMetric

		if c.Cluster.CertificateAuthorityData != "" {
			metricCollection, err = secondsToExpiryFromCertAsBase64String(c.Cluster.CertificateAuthorityData)

			if err != nil {
				return err
			}
		} else if c.Cluster.CertificateAuthority != "" {
			certFile := pathToFileFromKubeConfig(c.Cluster.CertificateAuthority, file)
			metricCollection, err = secondsToExpiryFromCertAsFile(certFile)

			if err != nil {
				return err
			}
		} else {
			return fmt.Errorf("Cluster %v does not have CertAuthority or CertAuthorityData", c.Name)
		}

		for _, metric := range metricCollection {
			metrics.KubeConfigExpirySeconds.WithLabelValues(file, "cluster", c.Name, nodeName).Set(metric.durationUntilExpiry)
			metrics.KubeConfigNotAfterTimestamp.WithLabelValues(file, "cluster", c.Name, nodeName).Set(metric.notAfter)
		}
	}

	for _, u := range k.Users {
		var metricCollection []certMetric

		if u.User.ClientCertificateData != "" {
			metricCollection, err = secondsToExpiryFromCertAsBase64String(u.User.ClientCertificateData)

			if err != nil {
				return err
			}
		} else if u.User.ClientCertificate != "" {
			certFile := pathToFileFromKubeConfig(u.User.ClientCertificate, file)
			metricCollection, err = secondsToExpiryFromCertAsFile(certFile)

			if err != nil {
				return err
			}
		} else {
			return fmt.Errorf("User %v does not have ClientCert or ClientCertData", u.Name)
		}

		for _, metric := range metricCollection {
			metrics.KubeConfigExpirySeconds.WithLabelValues(file, "user", u.Name, nodeName).Set(metric.durationUntilExpiry)
			metrics.KubeConfigNotAfterTimestamp.WithLabelValues(file, "user", u.Name, nodeName).Set(metric.notAfter)
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
