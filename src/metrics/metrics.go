package metrics

import "github.com/prometheus/client_golang/prometheus"

const (
	namespace = "cert_exporter"
)

var (
	ErrorTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "error_total",
			Help:      "Cert Exporter Errors",
		},
	)

	CertExpirySeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "cert_expires_in_seconds",
			Help:      "Number of seconds til the cert expires.",
		},
		[]string{"filename"},
	)

	KubeConfigExpirySeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "kubeconfig_expires_in_seconds",
			Help:      "Number of seconds til the cert in kubeconfig expires.",
		},
		[]string{"filename", "type", "name"},
	)
)

func init() {
	prometheus.MustRegister(ErrorTotal)
	prometheus.MustRegister(CertExpirySeconds)
	prometheus.MustRegister(KubeConfigExpirySeconds)
}
