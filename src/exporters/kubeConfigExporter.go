package exporters

import (
	"fmt"
	"path"

	"github.com/joe-elliott/cert-exporter/src/args"
	"github.com/joe-elliott/cert-exporter/src/kubeconfig"
	"github.com/joe-elliott/cert-exporter/src/metrics"
)

// KubeConfigExporter exports kubeconfig certs
type KubeConfigExporter struct {
	PasswordSpecs   []args.PasswordSpec
	DefaultPassword string
}

// NewKubeConfigExporter creates a new KubeConfigExporter with an optional password.
func NewKubeConfigExporter(specs []args.PasswordSpec, defaultPassword string) *KubeConfigExporter {
	return &KubeConfigExporter{PasswordSpecs: specs, DefaultPassword: defaultPassword}
}

// ExportMetrics exports all certs in the passed in kubeconfig file
func (c *KubeConfigExporter) ExportMetrics(file, nodeName string) error {
	k, err := kubeconfig.ParseKubeConfig(file)

	// Determine the password applicable to the kubeconfig file itself,
	// which will be used for embedded certificate data.
	passwordForKubeconfigItself := GetPasswordForFile(file, c.PasswordSpecs, c.DefaultPassword)

	if err != nil {
		return err
	}

	for _, clusterConfig := range k.Clusters {
		var metricCollection []certMetric
		if clusterConfig.Cluster.CertificateAuthorityData != "" {
			metricCollection, err = secondsToExpiryFromCertAsBase64String(clusterConfig.Cluster.CertificateAuthorityData, passwordForKubeconfigItself)

			if err != nil {
				return err
			}
		} else if clusterConfig.Cluster.CertificateAuthority != "" {
			certFile := pathToFileFromKubeConfig(clusterConfig.Cluster.CertificateAuthority, file)
			passwordForCertFile := GetPasswordForFile(certFile, c.PasswordSpecs, c.DefaultPassword)
			metricCollection, err = secondsToExpiryFromCertAsFile(certFile, passwordForCertFile)

			if err != nil {
				return err
			}
		} else {
			return fmt.Errorf("Cluster %v does not have CertAuthority or CertAuthorityData", clusterConfig.Name)
		}

		for _, metric := range metricCollection {
			metrics.KubeConfigExpirySeconds.WithLabelValues(file, "cluster", metric.cn, metric.issuer, clusterConfig.Name, nodeName).Set(metric.durationUntilExpiry)
			metrics.KubeConfigNotAfterTimestamp.WithLabelValues(file, "cluster", metric.cn, metric.issuer, clusterConfig.Name, nodeName).Set(metric.notAfter)
			metrics.KubeConfigNotBeforeTimestamp.WithLabelValues(file, "cluster", metric.cn, metric.issuer, clusterConfig.Name, nodeName).Set(metric.notBefore)
		}
	}

	for _, u := range k.Users {
		var metricCollection []certMetric

		if u.User.ClientCertificateData != "" {
			metricCollection, err = secondsToExpiryFromCertAsBase64String(u.User.ClientCertificateData, passwordForKubeconfigItself)

			if err != nil {
				return err
			}
		} else if u.User.ClientCertificate != "" {
			certFile := pathToFileFromKubeConfig(u.User.ClientCertificate, file)
			passwordForCertFile := GetPasswordForFile(certFile, c.PasswordSpecs, c.DefaultPassword)
			metricCollection, err = secondsToExpiryFromCertAsFile(certFile, passwordForCertFile)

			if err != nil {
				return err
			}
		} else {
			return fmt.Errorf("User %v does not have ClientCert or ClientCertData", u.Name)
		}

		for _, metric := range metricCollection {
			metrics.KubeConfigExpirySeconds.WithLabelValues(file, "user", metric.cn, metric.issuer, u.Name, nodeName).Set(metric.durationUntilExpiry)
			metrics.KubeConfigNotAfterTimestamp.WithLabelValues(file, "user", metric.cn, metric.issuer, u.Name, nodeName).Set(metric.notAfter)
			metrics.KubeConfigNotBeforeTimestamp.WithLabelValues(file, "user", metric.cn, metric.issuer, u.Name, nodeName).Set(metric.notBefore)
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
