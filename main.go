package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/klog"
)

var (
	prometheusListenAddress string
	prometheusPath          string
)

func init() {
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
