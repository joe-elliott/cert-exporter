# cert-exporter

[![Go Report Card](https://goreportcard.com/badge/github.com/joe-elliott/cert-exporter)](https://goreportcard.com/report/github.com/joe-elliott/cert-exporter) ![version](https://img.shields.io/badge/version-1.0.0-blue.svg?cacheSeconds=2592000)

Kubernetes uses PKI certificates for authentication between all major components.  These certs are critical for the operation of your cluster but are often opaque to an administrator.  This application is designed to parse certificates and export expiration information for Prometheus to scrape.

**WARNING** If you run this application in your cluster it will probably require elevated privileges of some kind.  Additionally you are exposing VERY sensitive information to it.  Review the source!

### Usage

cert-exporter supports x509 certificates on disk encoded in the [PEM format](https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail) as well as certs embedded or referenced from kubeconfig files.  Certificates are often stored both ways when building clusters.

See [deployment](https://github.com/joe-elliott/cert-exporter/blob/master/docs/deploy.md) for detailed information on running cert-exporter and examples of running it in a [kops](https://github.com/kubernetes/kops) cluster.

### Dashboard

After running cert-exporter in your cluster it's easy to build a [custom dashboard](https://github.com/joe-elliott/cert-exporter/blob/master/docs/sample-dashboard.yaml) to expose information about the certs in your cluster.

![cert-exporter dashboard](https://github.com/joe-elliott/cert-exporter/blob/master/docs/dashboard.png)

### Exported Metrics

cert-exporter exports the following metrics

```
# HELP cert_exporter_error_total Cert Exporter Errors
# TYPE cert_exporter_error_total counter
cert_exporter_error_total 0
# HELP cert_exporter_cert_expires_in_seconds Number of seconds til the cert expires.
# TYPE cert_exporter_cert_expires_in_seconds gauge
cert_exporter_cert_expires_in_seconds{filename="certsSibling/client.crt"} 8.639964560021e+06
# HELP cert_exporter_kubeconfig_expires_in_seconds Number of seconds til the cert in kubeconfig expires.
# TYPE cert_exporter_kubeconfig_expires_in_seconds gauge
cert_exporter_kubeconfig_expires_in_seconds{filename="kubeConfigSibling/kubeconfig",name="cluster1",type="cluster"} 8.639964559682e+06
cert_exporter_kubeconfig_expires_in_seconds{filename="kubeConfigSibling/kubeconfig",name="user1",type="user"} 8.639964559249e+06
```

**cert_exporter_error_total**  
The total number of unexpected errors encountered by cert-exporter.  A good metric to watch to feel comfortable certs are being exported properly.

**cert_exporter_cert_expires_in_seconds**  
The number of seconds until a certificate stored in the PEM format is expired.  The `filename` label indicates the exported cert.

**cert_exporter_kubeconfig_expires_in_seconds**
The number of seconds until a certificate stored in a kubeconfig expires.  The `filename`, `type`, and `name` labels indicate the kubeconfig, cluster or user node and name of the node.  See details [here](https://kubernetes.io/docs/tasks/access-application-cluster/configure-access-multiple-clusters/).

### Other Docs
- [Testing](https://github.com/joe-elliott/cert-exporter/blob/master/docs/testing.md)
  - An overview of the testing scripts and how to run them.
- [Deployment](https://github.com/joe-elliott/cert-exporter/blob/master/docs/deploy.md)
  - Information on how to deploy cert-exporter as well as examples for a kops cluster.