package exporters

import (
	"fmt"
	"strings"
	"time"

	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
)

type certMetric struct {
	durationUntilExpiry float64
	notAfter            float64
	issuer              string
	cn, subject         string
	subjectSAN          string
}

func secondsToExpiryFromCertAsFile(file string) (certMetric, error) {
	certBytes, err := ioutil.ReadFile(file)
	if err != nil {
		return certMetric{}, err
	}

	return secondsToExpiryFromCertAsBytes(certBytes)
}

func secondsToExpiryFromCertAsBase64String(s string) (certMetric, error) {
	certBytes, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return certMetric{}, err
	}

	return secondsToExpiryFromCertAsBytes(certBytes)
}

func secondsToExpiryFromCertAsBytes(certBytes []byte) (certMetric, error) {
	var metric certMetric
	block, _ := pem.Decode(certBytes)
	if block == nil {
		return metric, fmt.Errorf("Failed to parse as a pem")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return metric, err
	}

	metric.notAfter = float64(cert.NotAfter.Unix())
	metric.durationUntilExpiry = time.Until(cert.NotAfter).Seconds()
	metric.cn = cert.Subject.CommonName // for backward-compatibility, keep the cn field

	subject := fmt.Sprintf("CN=%s", cert.Subject.CommonName)
	if len(cert.Issuer.Organization) > 0 {
		subject = subject + fmt.Sprintf(" O=%s", strings.Join(cert.Issuer.Organization, ","))
	}
	if len(cert.Issuer.OrganizationalUnit) > 0 {
		subject = subject + fmt.Sprintf(" OU=%s", strings.Join(cert.Issuer.OrganizationalUnit, ","))
	}
	metric.subject = subject

	issuer := fmt.Sprintf("CN=%s", cert.Issuer.CommonName)
	if len(cert.Issuer.Organization) > 0 {
		issuer = issuer + fmt.Sprintf(" O=%s", strings.Join(cert.Issuer.Organization, ","))
	}
	if len(cert.Issuer.OrganizationalUnit) > 0 {
		issuer = issuer + fmt.Sprintf(" OU=%s", strings.Join(cert.Issuer.OrganizationalUnit, ","))
	}
	metric.issuer = issuer

	subjectSAN := []string{}
	for _, dns := range cert.DNSNames {
		subjectSAN = append(subjectSAN, fmt.Sprintf("DNS:%s", dns))
	}
	for _, ip := range cert.IPAddresses {
		subjectSAN = append(subjectSAN, fmt.Sprintf("IP:%s", ip.String()))
	}
	metric.subjectSAN = strings.Join(subjectSAN, " ")
	return metric, nil
}
