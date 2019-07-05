package exporters

import (
	"fmt"
	"time"
	"path"

	"io/ioutil"
	"crypto/x509"
	"encoding/pem"
	"encoding/base64"

	"github.com/joe-elliott/cert-exporter/src/kubeconfig"
	"github.com/joe-elliott/cert-exporter/src/metrics"
)


type KubeConfigExporter struct {

}

func (c KubeConfigExporter) ExportMetrics(file string) error {
	k, err := kubeconfig.ParseKubeConfig(file)

	if err != nil {
		return err
	}

	for _, c := range k.Clusters {
		if c.Cluster.CertificateAuthorityData != "" {
			err = exportCertAsBase64String(c.Cluster.CertificateAuthorityData, file, "cluster", c.Name)

			if err != nil {
				return err
			}
		} else if c.Cluster.CertificateAuthority != "" { 
			err = exportCertAsFile(c.Cluster.CertificateAuthority, file, "cluster", c.Name)

			if err != nil {
				return err
			}
		} else {
			return fmt.Errorf("Cluster %v does not have CertAuthority or CertAuthorityData", c.Name)
		}
	}

	for _, u := range k.Users {
		if u.User.ClientCertificateData != "" {
			err = exportCertAsBase64String(u.User.ClientCertificateData, file, "user", u.Name)

			if err != nil {
				return err
			}
		} else if u.User.ClientCertificate != "" {
			err = exportCertAsFile(u.User.ClientCertificate, file, "user", u.Name)

			if err != nil {
				return err
			}
		} else {
			return fmt.Errorf("User %v does not have ClientCert or ClientCertData", u.Name)
		}
	}

	return nil
}

func exportCertAsFile(file string, kubeConfigFile string, configObject string, name string) error {
	kubeConfigPath := path.Dir(kubeConfigFile)
	file = path.Join(kubeConfigPath, file)

	certBytes, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}

	return exportCertAsBytes(certBytes, kubeConfigFile, configObject, name)
}

func exportCertAsBase64String(s string, kubeConfigFile string, configObject string, name string) error {
	certBytes, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return err
	}

	return exportCertAsBytes(certBytes, kubeConfigFile, configObject, name)
}

func exportCertAsBytes(certBytes []byte, kubeConfigFile string, configObject string, name string) error {
	block, _ := pem.Decode(certBytes)
	if block == nil {
		return fmt.Errorf("Failed to parse as a pem")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	durationUntilExpiry := time.Until(cert.NotAfter)
	metrics.KubeConfigExpirySeconds.WithLabelValues(kubeConfigFile, configObject, name).Set(durationUntilExpiry.Seconds())
	return nil
}