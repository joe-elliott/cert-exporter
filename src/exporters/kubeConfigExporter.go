package exporters

import (
	"fmt"
	"time"

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
		} else {

		}
	}

	for _, u := range k.Users {
		if u.User.ClientCertificateData != "" {
			err = exportCertAsBase64String(u.User.ClientCertificateData, file, "user", u.Name)

			if err != nil {
				return err
			}
		} else if u.User.ClientCertificate != "" { 
		} else {

		}
	}



	return nil
}

func exportCertAsBase64String(s string, filename string, configObject string, name string) error {
	certBytes, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(certBytes)
	if block == nil {
		return fmt.Errorf("Failed to parse as a pem")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	durationUntilExpiry := time.Until(cert.NotAfter)
	metrics.KubeConfigExpirySeconds.WithLabelValues(filename, configObject, name).Set(durationUntilExpiry.Seconds())
	return nil
}


