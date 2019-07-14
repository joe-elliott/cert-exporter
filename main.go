package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/joe-elliott/cert-exporter/src/args"
	"github.com/joe-elliott/cert-exporter/src/checkers"
	"github.com/joe-elliott/cert-exporter/src/exporters"

	"github.com/golang/glog"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	includeCertGlobs        args.GlobArgs
	excludeCertGlobs        args.GlobArgs
	includeKubeConfigGlobs  args.GlobArgs
	excludeKubeConfigGlobs  args.GlobArgs
	prometheusListenAddress string
	prometheusPath          string
	pollingPeriod           time.Duration
	kubeconfigPath          string
	secretsLabelSelector    args.GlobArgs
	secretsDataGlob         string
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
	flag.StringVar(&secretsDataGlob, "secrets-data-glob", "*.crt", "Glob to match against secret data keys.")
	flag.Var(&secretsLabelSelector, "secrets-label-selector", "Label selector to find secrets to publish as metrics.")
}

func main() {
	flag.Parse()

	glog.Info("Application Starting")

	if len(includeCertGlobs) > 0 {
		certChecker := checkers.NewCertChecker(pollingPeriod, includeCertGlobs, excludeCertGlobs, &exporters.CertExporter{})
		go certChecker.StartChecking()
	}

	if len(includeKubeConfigGlobs) > 0 {
		configChecker := checkers.NewCertChecker(pollingPeriod, includeKubeConfigGlobs, excludeKubeConfigGlobs, &exporters.KubeConfigExporter{})
		go configChecker.StartChecking()
	}

	if len(secretsLabelSelector) > 0 {
		configChecker := checkers.NewSecretChecker(pollingPeriod, secretsLabelSelector, secretsDataGlob, kubeconfigPath, &exporters.SecretExporter{})
		go configChecker.StartChecking()
	}

	http.Handle(prometheusPath, promhttp.Handler())
	log.Fatal(http.ListenAndServe(prometheusListenAddress, nil))
}
