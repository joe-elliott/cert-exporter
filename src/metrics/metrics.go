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
		[]string{"filename", "issuer", "cn", "nodename"},
	)

	// CertNotAfterTimestamp is a prometheus gauge that indicates the NotAfter timestamp.
	CertNotAfterTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "cert_not_after_timestamp",
			Help:      "Timestamp of when the certificate expires.",
		},
		[]string{"filename", "issuer", "cn", "nodename"},
	)

	// KubeConfigExpirySeconds is a prometheus gauge that indicates the number of seconds until a kubeconfig certificate expires.
	KubeConfigExpirySeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "kubeconfig_expires_in_seconds",
			Help:      "Number of seconds til the cert in the kubeconfig expires.",
		},
		[]string{"filename", "type", "name", "nodename"},
	)

	// KubeConfigNotAfterTimestamp is a prometheus gauge that indicates the NotAfter timestamp.
	KubeConfigNotAfterTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "kubeconfig_not_after_timestamp",
			Help:      "Expiration timestamp for cert in the kubeconfig.",
		},
		[]string{"filename", "type", "name", "nodename"},
	)

	// SecretExpirySeconds is a prometheus gauge that indicates the number of seconds until a kubernetes secret certificate expires
	SecretExpirySeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "secret_expires_in_seconds",
			Help:      "Number of seconds til the cert in the secret expires.",
		},
		[]string{"key_name", "issuer", "cn", "secret_name", "secret_namespace"},
	)

	// SecretNotAfterTimestamp is a prometheus gauge that indicates the NotAfter timestamp.
	SecretNotAfterTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "secret_not_after_timestamp",
			Help:      "Expiration timestamp for cert in the secret.",
		},
		[]string{"key_name", "issuer", "cn", "secret_name", "secret_namespace"},
	)

	// AwsCertExpirySeconds is a prometheus gauge that indicates the number of seconds until certificates on AWS expires.
	AwsCertExpirySeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "cert_expires_in_seconds",
			Help:      "Number of seconds til the cert expires.",
		},
		[]string{"filename", "issuer", "cn"},
	)
)

func init() {
	prometheus.MustRegister(ErrorTotal)
	//prometheus.MustRegister(CertExpirySeconds)
	//prometheus.MustRegister(CertNotAfterTimestamp)
	//prometheus.MustRegister(KubeConfigExpirySeconds)
	//prometheus.MustRegister(KubeConfigNotAfterTimestamp)
	//prometheus.MustRegister(SecretExpirySeconds)
	//prometheus.MustRegister(SecretNotAfterTimestamp)
	prometheus.MustRegister(AwsCertExpirySeconds)
}
