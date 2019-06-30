package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/joe-elliott/cert-exporter/src/globargs"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/klog"
)

var (
	includeGlobs            globargs.Args
	excludeGlobs            globargs.Args
	prometheusListenAddress string
	prometheusPath          string
)

func init() {

	flag.Var(&includeGlobs, "include-glob", "File globs to include when looking for certs.")
	flag.Var(&excludeGlobs, "exclude-glob", "File globs to exclude when looking for certs.")

	flag.StringVar(&prometheusPath, "prometheus-path", "/metrics", "The path to publish Prometheus metrics to.")
	flag.StringVar(&prometheusListenAddress, "prometheus-listen-address", ":8080", "The address to listen on for Prometheus scrapes.")

	klog.InitFlags(nil)
}

func main() {
	klog.Info("Application Starting")

	flag.Parse()

	http.Handle(prometheusPath, promhttp.Handler())
	log.Fatal(http.ListenAndServe(prometheusListenAddress, nil))
}
