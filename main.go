package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/joe-elliott/cert-exporter/src/args"
	"github.com/joe-elliott/cert-exporter/src/checkers"
	"github.com/joe-elliott/cert-exporter/src/exporters"
	"github.com/joe-elliott/cert-exporter/src/metrics"
)

var (
	version = "unknown"
	commit  = "unknown"
	date    = "unknown"
)

var (
	includeCertGlobs                  args.GlobArgs
	excludeCertGlobs                  args.GlobArgs
	includeKubeConfigGlobs            args.GlobArgs
	excludeKubeConfigGlobs            args.GlobArgs
	prometheusExporterMetricsDisabled bool
	prometheusListenAddress           string
	prometheusPath                    string
	pollingPeriod                     time.Duration
	kubeconfigPath                    string
	secretsLabelSelector              args.GlobArgs
	secretsAnnotationSelector         args.GlobArgs
	secretsNamespace                  string
	secretsListOfNamespaces           string
	includeSecretsDataGlobs           args.GlobArgs
	excludeSecretsDataGlobs           args.GlobArgs
	includeSecretsTypes               args.GlobArgs
	configMapsLabelSelector           args.GlobArgs
	configMapsAnnotationSelector      args.GlobArgs
	configMapsNamespace               string
	configMapsListOfNamespaces        string
	includeConfigMapsDataGlobs        args.GlobArgs
	excludeConfigMapsDataGlobs        args.GlobArgs
	webhookCheckEnabled               bool
	webhooksLabelSelector             args.GlobArgs
	webhooksAnnotationSelector        args.GlobArgs
	awsAccount                        string
	awsRegion                         string
	awsSecrets                        args.GlobArgs
	certRequestsEnabled               bool
	certRequestsLabelSelector         args.GlobArgs
	certRequestsAnnotationSelector    args.GlobArgs
	certRequestsNamespace             string
	certRequestsListOfNamespaces      string
)

func init() {
	flag.Var(&includeCertGlobs, "include-cert-glob", "File globs to include when looking for certs.")
	flag.Var(&excludeCertGlobs, "exclude-cert-glob", "File globs to exclude when looking for certs.")
	flag.Var(&includeKubeConfigGlobs, "include-kubeconfig-glob", "File globs to include when looking for kubeconfigs.")
	flag.Var(&excludeKubeConfigGlobs, "exclude-kubeconfig-glob", "File globs to exclude when looking for kubeconfigs.")
	flag.StringVar(&prometheusPath, "prometheus-path", "/metrics", "The path to publish Prometheus metrics to.")
	flag.StringVar(&prometheusListenAddress, "prometheus-listen-address", ":8080", "The address to listen on for Prometheus scrapes.")
	flag.BoolVar(&prometheusExporterMetricsDisabled, "prometheus-disable-exporter-metrics", false, "Exclude metrics about the exporter itself (promhttp_*, process_*, go_*).")
	flag.DurationVar(&pollingPeriod, "polling-period", time.Hour, "Periodic interval in which to check certs.")

	flag.StringVar(&kubeconfigPath, "kubeconfig", "", "Path to a kubeconfig. Only required if out-of-cluster.")
	flag.Var(&secretsLabelSelector, "secrets-label-selector", "Label selector to find secrets to publish as metrics.")
	flag.Var(&secretsAnnotationSelector, "secrets-annotation-selector", "Annotation selector to find secrets to publish as metrics.")
	flag.StringVar(&secretsNamespace, "secrets-namespace", "", "Kubernetes namespace to list secrets.")
	flag.StringVar(&secretsListOfNamespaces, "secrets-namespaces", "", "Kubernetes comma-delimited list of namespaces to search for secrets.")
	flag.Var(&includeSecretsDataGlobs, "secrets-include-glob", "Secret globs to include when looking for secret data keys (Default \"*\").")
	flag.Var(&includeSecretsTypes, "secret-include-types", "Select only specific a secret type (Default nil).")
	flag.Var(&excludeSecretsDataGlobs, "secrets-exclude-glob", "Secret globs to exclude when looking for secret data keys.")

	flag.Var(&configMapsLabelSelector, "configmaps-label-selector", "Label selector to find configmaps to publish as metrics.")
	flag.Var(&configMapsAnnotationSelector, "configmaps-annotation-selector", "Annotation selector to find configmaps to publish as metrics.")
	flag.StringVar(&configMapsNamespace, "configmaps-namespace", "", "Kubernetes namespace to list configmaps.")
	flag.StringVar(&configMapsListOfNamespaces, "configmaps-namespaces", "", "Kubernetes comma-delimited list of namespaces to search for configmaps.")
	flag.Var(&includeConfigMapsDataGlobs, "configmaps-include-glob", "Configmap globs to include when looking for configmap data keys (Default \"*\").")
	flag.Var(&excludeConfigMapsDataGlobs, "configmaps-exclude-glob", "Configmap globs to exclude when looking for configmap data keys.")

	flag.BoolVar(&webhookCheckEnabled, "enable-webhook-cert-check", false, "Enable webhook cert check.")
	flag.Var(&webhooksLabelSelector, "webhooks-label-selector", "Label selector to find webhooks to publish as metrics.")
	flag.Var(&webhooksAnnotationSelector, "webhooks-annotation-selector", "Annotation selector to find webhooks to publish as metrics.")

	flag.StringVar(&awsAccount, "aws-account", "", "AWS account to search for secrets in")
	flag.StringVar(&awsRegion, "aws-region", "", "AWS region to search for secrets in")
	flag.Var(&awsSecrets, "aws-secret", "AWS secrets to export")

	flag.BoolVar(&certRequestsEnabled, "enable-certrequests-check", false, "Enable certrequests check.")
	flag.Var(&certRequestsLabelSelector, "certrequests-label-selector", "Label selector to find certrequests to publish as metrics.")
	flag.Var(&certRequestsAnnotationSelector, "certrequests-annotation-selector", "Annotation selector to find certrequests to publish as metrics.")
	flag.StringVar(&certRequestsNamespace, "certrequests-namespace", "", "Kubernetes namespace to list certrequests.")
	flag.StringVar(&certRequestsListOfNamespaces, "certrequests-namespaces", "", "Kubernetes comma-delimited list of namespaces to search for certrequests.")

}

func main() {
	flag.Parse()
	metrics.Init(prometheusExporterMetricsDisabled)

	glog.Infof("Starting cert-exporter (version %s; commit %s; date %s)", version, commit, date)

	if len(includeCertGlobs) > 0 {
		certChecker := checkers.NewCertChecker(pollingPeriod, includeCertGlobs, excludeCertGlobs, os.Getenv("NODE_NAME"), &exporters.CertExporter{})
		go certChecker.StartChecking()
	}

	if len(includeKubeConfigGlobs) > 0 {
		configChecker := checkers.NewCertChecker(pollingPeriod, includeKubeConfigGlobs, excludeKubeConfigGlobs, os.Getenv("NODE_NAME"), &exporters.KubeConfigExporter{})
		go configChecker.StartChecking()
	}

	if len(secretsLabelSelector) > 0 || len(secretsAnnotationSelector) > 0 || len(includeSecretsDataGlobs) > 0 {
		if len(includeSecretsDataGlobs) == 0 {
			includeSecretsDataGlobs = args.GlobArgs([]string{"*"})
		}
		secretsNamespaces := getSanitizedNamespaceList(secretsListOfNamespaces, secretsNamespace)

		configChecker := checkers.NewSecretChecker(pollingPeriod, secretsLabelSelector, includeSecretsDataGlobs, excludeSecretsDataGlobs, secretsAnnotationSelector, secretsNamespaces, kubeconfigPath, &exporters.SecretExporter{}, includeSecretsTypes)
		go configChecker.StartChecking()
	}

	if len(certRequestsLabelSelector) > 0 || len(certRequestsAnnotationSelector) > 0 || certRequestsEnabled {
		certRequestNamespaces := getSanitizedNamespaceList(certRequestsListOfNamespaces, certRequestsNamespace)

		configChecker := checkers.NewCertRequestChecker(pollingPeriod, certRequestsLabelSelector, secretsAnnotationSelector, certRequestNamespaces, kubeconfigPath, &exporters.CertRequestExporter{})
		go configChecker.StartChecking()

	}

	if len(awsAccount) > 0 && len(awsRegion) > 0 && len(awsSecrets) > 0 {
		glog.Infof("Starting check for AWS Secrets Manager in Account %s and Region %s and Secrets %s", awsAccount, awsRegion, awsSecrets)
		awsChecker := checkers.NewAwsChecker(awsAccount, awsRegion, awsSecrets, pollingPeriod, &exporters.AwsExporter{})
		go awsChecker.StartChecking()
	}

	if len(configMapsLabelSelector) > 0 || len(configMapsAnnotationSelector) > 0 || len(includeConfigMapsDataGlobs) > 0 {
		if len(includeConfigMapsDataGlobs) == 0 {
			includeConfigMapsDataGlobs = args.GlobArgs([]string{"*"})
		}
		configMapsNamespaces := getSanitizedNamespaceList(configMapsListOfNamespaces, configMapsNamespace)

		configChecker := checkers.NewConfigMapChecker(pollingPeriod, configMapsLabelSelector, includeConfigMapsDataGlobs, excludeConfigMapsDataGlobs, configMapsAnnotationSelector, configMapsNamespaces, kubeconfigPath, &exporters.ConfigMapExporter{})
		go configChecker.StartChecking()
	}

	if webhookCheckEnabled {
		configChecker := checkers.NewWebhookChecker(pollingPeriod, webhooksLabelSelector, webhooksAnnotationSelector, kubeconfigPath, &exporters.WebhookExporter{})
		go configChecker.StartChecking()
	}

	handler := promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{})

	if !prometheusExporterMetricsDisabled {
		handler = promhttp.InstrumentMetricHandler(prometheus.DefaultRegisterer, handler)
	}

	http.Handle(prometheusPath, handler)
	log.Fatal(http.ListenAndServe(prometheusListenAddress, nil))
}

// Get the trimmed and sanitized list of namespaces
func getSanitizedNamespaceList(rawListOfNamespaces, namespace string) []string {
	var selected []string

	if len(rawListOfNamespaces) > 0 {
		provided := strings.Split(rawListOfNamespaces, ",")
		for _, v := range provided {
			v = strings.TrimSpace(v)
			if v != "" {
				selected = append(selected, v)
			}
		}
	}

	if len(namespace) > 0 {
		selected = append(selected, namespace)
	}

	if len(selected) == 0 {
		return []string{""}
	}

	return selected
}
