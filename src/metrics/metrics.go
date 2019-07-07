package metrics

import "github.com/prometheus/client_golang/prometheus"

const (
	namespace = "cert_exporter"
)

var (
	// ErrorTotal is a prometheus counter that indicates the total number of unexpected errors encountered by the application
	ErrorTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "error_total",
			Help:      "Cert Exporter Errors",
		},
	)

	// CertExpirySeconds is a prometheus gauge that indicates the number of seconds until certificates on disk expires.
	CertExpirySeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "cert_expires_in_seconds",
			Help:      "Number of seconds til the cert expires.",
		},
		[]string{"filename"},
	)

	// KubeConfigExpirySeconds is a prometheus gauge that indicates the number of seconds until a kubeconfig certificate expires.
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
