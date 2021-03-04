package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang/glog"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/hakhundov/cert-exporter/src/args"
	"github.com/hakhundov/cert-exporter/src/checkers"
	"github.com/hakhundov/cert-exporter/src/exporters"
)

var (
	version = "unknown"
	commit  = "unknown"
	date    = "unknown"
)

var (
	includeCertGlobs          args.GlobArgs
	excludeCertGlobs          args.GlobArgs
	includeKubeConfigGlobs    args.GlobArgs
	excludeKubeConfigGlobs    args.GlobArgs
	prometheusListenAddress   string
	prometheusPath            string
	pollingPeriod             time.Duration
	kubeconfigPath            string
	secretsLabelSelector      args.GlobArgs
	secretsAnnotationSelector args.GlobArgs
	secretsNamespace          string
	includeSecretsDataGlobs   args.GlobArgs
	excludeSecretsDataGlobs   args.GlobArgs
	includeSecretsTypes       args.GlobArgs
)

func init() {
	flag.Var(&includeCertGlobs, "include-cert-glob", "File globs to include when looking for certs.")
	flag.Var(&excludeCertGlobs, "exclude-cert-glob", "File globs to exclude when looking for certs.")
	flag.Var(&includeKubeConfigGlobs, "include-kubeconfig-glob", "File globs to include when looking for kubeconfigs.")
	flag.Var(&excludeKubeConfigGlobs, "exclude-kubeconfig-glob", "File globs to exclude when looking for kubeconfigs.")
	flag.StringVar(&prometheusPath, "prometheus-path", "/metrics", "The path to publish Prometheus metrics to.")
	flag.StringVar(&prometheusListenAddress, "prometheus-listen-address", ":8080", "The address to listen on for Prometheus scrapes.")
	flag.DurationVar(&pollingPeriod, "polling-period", time.Hour, "Periodic interval in which to check certs.")

	flag.StringVar(&kubeconfigPath, "kubeconfig", "", "Path to a kubeconfig. Only required if out-of-cluster.")
	flag.Var(&secretsLabelSelector, "secrets-label-selector", "Label selector to find secrets to publish as metrics.")
	flag.Var(&secretsAnnotationSelector, "secrets-annotation-selector", "Annotation selector to find secrets to publish as metrics.")
	flag.StringVar(&secretsNamespace, "secrets-namespace", "", "Kubernetes namespace to list secrets.")
	flag.Var(&includeSecretsDataGlobs, "secrets-include-glob", "Secret globs to include when looking for secret data keys (Default \"*\").")
	flag.Var(&includeSecretsTypes, "secret-include-types", "Select only specific a secret type (Default nil).")
	flag.Var(&excludeSecretsDataGlobs, "secrets-exclude-glob", "Secret globs to exclude when looking for secret data keys.")
}

func main() {
	flag.Parse()

	glog.Infof("Starting cert-exporter (version %s; commit %s; date %s)", version, commit, date)

	certChecker := checkers.NewAwsChecker(pollingPeriod, os.Getenv("ENV"), &exporters.AwsExporter{})
	go certChecker.StartChecking()

	http.Handle(prometheusPath, promhttp.Handler())
	log.Fatal(http.ListenAndServe(prometheusListenAddress, nil))
}
