package exporters

import (
	"fmt"
	"path"

	"github.com/joe-elliott/cert-exporter/src/kubeconfig"
	"github.com/joe-elliott/cert-exporter/src/metrics"
)

// CertExporter exports kubeconfig certs
type KubeConfigExporter struct {
}

// ExportMetrics exports all certs in the passed in kubeconfig file
func (c KubeConfigExporter) ExportMetrics(file string) error {
	k, err := kubeconfig.ParseKubeConfig(file)

	if err != nil {
		return err
	}

	for _, c := range k.Clusters {
		var duration float64

		if c.Cluster.CertificateAuthorityData != "" {
			duration, err = secondsToExpiryFromCertAsBase64String(c.Cluster.CertificateAuthorityData)

			if err != nil {
				return err
			}
		} else if c.Cluster.CertificateAuthority != "" {
			certFile := pathToFileFromKubeConfig(c.Cluster.CertificateAuthority, file)
			duration, err = secondsToExpiryFromCertAsFile(certFile)

			if err != nil {
				return err
			}
		} else {
			return fmt.Errorf("Cluster %v does not have CertAuthority or CertAuthorityData", c.Name)
		}

		metrics.KubeConfigExpirySeconds.WithLabelValues(file, "cluster", c.Name).Set(duration)
	}

	for _, u := range k.Users {
		var duration float64

		if u.User.ClientCertificateData != "" {
			duration, err = secondsToExpiryFromCertAsBase64String(u.User.ClientCertificateData)

			if err != nil {
				return err
			}
		} else if u.User.ClientCertificate != "" {
			certFile := pathToFileFromKubeConfig(u.User.ClientCertificate, file)
			duration, err = secondsToExpiryFromCertAsFile(certFile)

			if err != nil {
				return err
			}
		} else {
			return fmt.Errorf("User %v does not have ClientCert or ClientCertData", u.Name)
		}

		metrics.KubeConfigExpirySeconds.WithLabelValues(file, "user", u.Name).Set(duration)
	}

	return nil
}

func pathToFileFromKubeConfig(file string, kubeConfigFile string) string {
	if !path.IsAbs(file) {
		kubeConfigPath := path.Dir(kubeConfigFile)
		file = path.Join(kubeConfigPath, file)
	}

	return file
}
