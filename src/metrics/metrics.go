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
	// Discovered is a prometheus guage that indicates the sum of discovered certificates after taking into account include and exclude globs
	Discovered = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "discovered",
			Help:      "Cert Exporter Discovered Certificates",
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

	// CertNotBeforeTimestamp is a prometheus gauge that indicates the NotBefore timestamp.
	CertNotBeforeTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "cert_not_before_timestamp",
			Help:      "Timestamp of when the certificate becomes valid.",
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
		[]string{"filename", "type", "cn", "issuer", "name", "nodename"},
	)

	// KubeConfigNotAfterTimestamp is a prometheus gauge that indicates the NotAfter timestamp.
	KubeConfigNotAfterTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "kubeconfig_not_after_timestamp",
			Help:      "Expiration timestamp for cert in the kubeconfig.",
		},
		[]string{"filename", "type", "cn", "issuer", "name", "nodename"},
	)

	// KubeConfigNotBeforeTimestamp is a prometheus gauge that indicates the NotBefore timestamp.
	KubeConfigNotBeforeTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "kubeconfig_not_before_timestamp",
			Help:      "Activation timestamp for cert in the kubeconfig.",
		},
		[]string{"filename", "type", "cn", "issuer", "name", "nodename"},
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
	
	// SecretNotBeforeTimestamp is a prometheus gauge that indicates the NotBefore timestamp.
	SecretNotBeforeTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "secret_not_before_timestamp",
			Help:      "Activation timestamp for cert in the secret.",
		},
		[]string{"key_name", "issuer", "cn", "secret_name", "secret_namespace"},
	)

	// CertRequestExpirySeconds is a prometheus gauge that indicates the number of seconds until a certificate in a cert-manager certificate request  expires
	CertRequestExpirySeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "certrequest_expires_in_seconds",
			Help:      "Number of seconds til the cert in the certrequest expires.",
		},
		[]string{"issuer", "cn", "cert_request", "certrequest_namespace"},
	)

	// CertRequestNotAfterTimestamp is a prometheus gauge that indicates the NotAfter timestamp.
	CertRequestNotAfterTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "certrequest_not_after_timestamp",
			Help:      "Expiration timestamp for cert in the certrequest.",
		},
		[]string{"issuer", "cn", "cert_request", "certrequest_namespace"},
	)
	
	// CertRequestNotBeforeTimestamp is a prometheus gauge that indicates the NotBefore timestamp.
	CertRequestNotBeforeTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "certrequest_not_before_timestamp",
			Help:      "Activation timestamp for cert in the certrequest.",
		},
		[]string{"issuer", "cn", "cert_request", "certrequest_namespace"},
	)

	// AwsCertExpirySeconds is a prometheus gauge that indicates the number of seconds until certificates on AWS expires.
	AwsCertExpirySeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "cert_expires_in_seconds_aws",
			Help:      "Number of seconds til the cert expires.",
		},
		[]string{"secretName", "key", "file", "issuer", "cn"},
	)

	// ConfigMapExpirySeconds is a prometheus gauge that indicates the number of seconds until a kubernetes configmap certificate expires
	ConfigMapExpirySeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "configmap_expires_in_seconds",
			Help:      "Number of seconds til the cert in the configmap expires.",
		},
		[]string{"key_name", "issuer", "cn", "configmap_name", "configmap_namespace"},
	)

	// ConfigMapNotAfterTimestamp is a prometheus gauge that indicates the NotAfter timestamp.
	ConfigMapNotAfterTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "configmap_not_after_timestamp",
			Help:      "Expiration timestamp for cert in the configmap.",
		},
		[]string{"key_name", "issuer", "cn", "configmap_name", "configmap_namespace"},
	)
	
	// ConfigMapNotBeforeTimestamp is a prometheus gauge that indicates the NotBefore timestamp.
	ConfigMapNotBeforeTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "configmap_not_before_timestamp",
			Help:      "Activation timestamp for cert in the configmap.",
		},
		[]string{"key_name", "issuer", "cn", "configmap_name", "configmap_namespace"},
	)

	// WebhookExpirySeconds is a prometheus gauge that indicates the number of seconds until a kubernetes webhook certificate expires
	WebhookExpirySeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "webhook_expires_in_seconds",
			Help:      "Number of seconds til the cert in the webhook expires.",
		},
		[]string{"type_name", "issuer", "cn", "webhook_name", "admission_review_version_name"},
	)

	// WebhookNotAfterTimestamp is a prometheus gauge that indicates the NotAfter timestamp.
	WebhookNotAfterTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "webhook_not_after_timestamp",
			Help:      "Expiration timestamp for cert in the webhook.",
		},
		[]string{"type_name", "issuer", "cn", "webhook_name", "admission_review_version_name"},
	)
	
	// WebhookNotBeforeTimestamp is a prometheus gauge that indicates the NotBefore timestamp.
	WebhookNotBeforeTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "webhook_not_before_timestamp",
			Help:      "Activation timestamp for cert in the webhook.",
		},
		[]string{"type_name", "issuer", "cn", "webhook_name", "admission_review_version_name"},
	)
)

func Init(prometheusExporterMetricsDisabled bool, registry *prometheus.Registry) {
	var registerer prometheus.Registerer

	if registry != nil {
		registerer = registry
	} else if prometheusExporterMetricsDisabled {
		emptyRegistry := prometheus.NewRegistry()
		prometheus.DefaultRegisterer = emptyRegistry
		prometheus.DefaultGatherer = emptyRegistry
		registerer = emptyRegistry
	} else {
		registerer = prometheus.DefaultRegisterer
	}

	registerer.MustRegister(ErrorTotal)
  registerer.MustRegister(Discovered)
	registerer.MustRegister(CertExpirySeconds)
	registerer.MustRegister(CertNotAfterTimestamp)
	registerer.MustRegister(CertNotBeforeTimestamp)
	registerer.MustRegister(KubeConfigExpirySeconds)
	registerer.MustRegister(KubeConfigNotAfterTimestamp)
	registerer.MustRegister(KubeConfigNotBeforeTimestamp)
	registerer.MustRegister(SecretExpirySeconds)
	registerer.MustRegister(SecretNotAfterTimestamp)
	registerer.MustRegister(SecretNotBeforeTimestamp)
	registerer.MustRegister(CertRequestExpirySeconds)
	registerer.MustRegister(CertRequestNotAfterTimestamp)
	registerer.MustRegister(CertRequestNotBeforeTimestamp)
	registerer.MustRegister(ConfigMapExpirySeconds)
	registerer.MustRegister(ConfigMapNotAfterTimestamp)
	registerer.MustRegister(ConfigMapNotBeforeTimestamp)
	registerer.MustRegister(WebhookExpirySeconds)
	registerer.MustRegister(WebhookNotAfterTimestamp)
	registerer.MustRegister(WebhookNotBeforeTimestamp)
	registerer.MustRegister(AwsCertExpirySeconds)
}
