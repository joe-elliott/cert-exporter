package exporters

import (
	"fmt"

	"github.com/joe-elliott/cert-exporter/src/kubeconfig"
)


type KubeConfigExporter struct {

}

func (c KubeConfigExporter) ExportMetrics(file string) error {
	k, err := kubeconfig.ParseKubeConfig(file)

	if err != nil {
		return err
	}

	for c := range k.Clusters {
		fmt.Printf("%v\n", c)
	}

	for u := range k.Users {
		fmt.Printf("%v\n", u)
	}

	/*block, _ := pem.Decode(certBytes)
	if block == nil {
		return fmt.Errorf("Failed to parse %v as a pem", file)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	durationUntilExpiry := time.Until(cert.NotAfter)
	metrics.CertExpirySeconds.WithLabelValues(file).Set(durationUntilExpiry.Seconds())*/

	return nil
}


