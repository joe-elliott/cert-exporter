# cert-exporter

[![Go Report Card](https://goreportcard.com/badge/github.com/hakhundov/cert-exporter)](https://goreportcard.com/report/github.com/hakhundov/cert-exporter) ![version](https://img.shields.io/badge/version-2.5.0-blue.svg?cacheSeconds=2592000)

Kubernetes uses PKI certificates for authentication between all major components.  These certs are critical for the operation of your cluster but are often opaque to an administrator.  This application is designed to parse certificates and export expiration information for Prometheus to scrape.

**WARNING** If you run this application in your cluster it will probably require elevated privileges of some kind.  Additionally you are exposing VERY sensitive information to it.  Review the source!

### Usage

cert-exporter can publish metrics about 

- x509 certificates on disk encoded in the [PEM format](https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail) 
- Certs embedded or referenced from kubeconfig files.
- Certs stored in Kubernetes secrets.  This supports applications such as [cert-manager](https://github.com/jetstack/cert-manager).

See [deployment](./docs/deploy.md) for detailed information on running cert-exporter and examples of running it in a [kops](https://github.com/kubernetes/kops) cluster.

See [custom-secrets](./docs/examples/custom-secrets) for examples of how to run `cert-exporter` to scrape certificates in secrets managed by you (not cert-manager).

### Dashboard

After running cert-exporter in your cluster it's easy to build a [custom dashboard](./docs/sample-dashboard.json) to expose information about the certs in your cluster.

![cert-exporter dashboard](./docs/dashboard.png)

### Exported Metrics

cert-exporter exports the following metrics

```
# HELP cert_exporter_error_total Cert Exporter Errors
# TYPE cert_exporter_error_total counter
cert_exporter_error_total 0
# HELP cert_exporter_cert_expires_in_seconds Number of seconds til the cert expires.
# TYPE cert_exporter_cert_expires_in_seconds gauge
cert_exporter_cert_expires_in_seconds{filename="certsSibling/client.crt",issuer="root",nodename="master0"} 8.639964560021e+06
# HELP cert_exporter_kubeconfig_expires_in_seconds Number of seconds til the cert in kubeconfig expires.
# TYPE cert_exporter_kubeconfig_expires_in_seconds gauge
cert_exporter_kubeconfig_expires_in_seconds{filename="kubeConfigSibling/kubeconfig",name="cluster1",nodename="master0",type="cluster"} 8.639964559682e+06
cert_exporter_kubeconfig_expires_in_seconds{filename="kubeConfigSibling/kubeconfig",name="user1",nodename="master0",type="user"} 8.639964559249e+06
# HELP cert_exporter_secret_expires_in_seconds Number of seconds til the cert in the secret expires.
# TYPE cert_exporter_secret_expires_in_seconds gauge
cert_exporter_secret_expires_in_seconds{cn="example.com",issuer="example.com",key_name="ca.crt",secret_name="selfsigned-cert-tls",secret_namespace="cert-manager-test"} 8.6396867095666e+06
cert_exporter_secret_expires_in_seconds{cn="example.com",issuer="example.com",key_name="tls.crt",secret_name="selfsigned-cert-tls",secret_namespace="cert-manager-test"} 8.639686709417423e+06
```

**cert_exporter_error_total**  
The total number of unexpected errors encountered by cert-exporter.  A good metric to watch to feel comfortable certs are being exported properly.

**cert_exporter_cert_expires_in_seconds**  
The number of seconds until a certificate stored in the PEM format is expired.  The `filename`, `issuer`, `cn`, and `nodename` label indicates the exported cert.

**cert_exporter_kubeconfig_expires_in_seconds**  
The number of seconds until a certificate stored in a kubeconfig expires.  The `filename`, `type`, `name`, and `nodename` labels indicate the kubeconfig, cluster or user node and name of the node.  See details [here](https://kubernetes.io/docs/tasks/access-application-cluster/configure-access-multiple-clusters/).

**cert_exporter_secret_expires_in_seconds**
The number of seconds until a certificate stored in a kubernetes secret expires.  The `key_name`, `issuer`, `cn`, `secret_name`, and `secret_namespace` labels indicate the secret key, name and namespace. 

### Other Docs

- [Testing](./docs/testing.md)
  - An overview of the testing scripts and how to run them. It requires [kind](https://github.com/kubernetes-sigs/kind) CLI.
- [Deployment](./docs/deploy.md)
  - Information on how to deploy cert-exporter as well as examples for a kops cluster.
- [Daemonset for Prometheus-operator](./docs/daemonset-prom-operator.yaml)
  - How to deploy daemonset+service+servicemonitor+dashboard if you use [prometheus-operator](https://github.com/coreos/prometheus-operator) into the `monitoring` namespace
