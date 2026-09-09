# cert-exporter

[![Go Report Card](https://goreportcard.com/badge/github.com/joe-elliott/cert-exporter)](https://goreportcard.com/report/github.com/joe-elliott/cert-exporter) ![binary version](https://img.shields.io/badge/binary%20version-2.18.0-blue) ![helm version](https://img.shields.io/badge/helm%20version-3.15.0-blue)

Kubernetes uses PKI certificates for authentication between all major components.  These certs are critical for the operation of your cluster but are often opaque to an administrator.  This application is designed to parse certificates and export expiration information for Prometheus to scrape.

**WARNING** If you run this application in your cluster it will probably require elevated privileges of some kind.  Additionally you are exposing VERY sensitive information to it.  Review the source!

### Usage

cert-exporter can publish metrics about 

- x509 certificates on disk encoded in the [PEM format](https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail), [PKCS12 format](https://en.wikipedia.org/wiki/PKCS_12) or as a [Java KeyStore](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#KeystoreImplementation) (JKS)
  - password-protected keystores via `--cert-password-file`
- Certs embedded or referenced from kubeconfig files.
- Certs stored in Kubernetes 
  - secrets 
    - direct support for [cert-manager](https://github.com/jetstack/cert-manager)
    - support for password-protected certificates
  - configmaps
  - [admission webhooks](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/)
  - cert-manager [CertificateRequest](https://cert-manager.io/docs/usage/certificaterequest/)
- Certs stored in [AWS Secrets manager](https://aws.amazon.com/secrets-manager/)

See [deployment](./docs/deploy.md) for detailed information on running cert-exporter and examples of running it in a [kops](https://github.com/kubernetes/kops) cluster.

See [custom-secrets](./docs/examples/custom-secrets) for examples of how to run `cert-exporter` to scrape certificates in secrets managed by you (not cert-manager).

To enable and scrape certificates from AWS secrets, do the following:
```
go run main.go --aws-account=<account_number> --aws-region=<region> --aws-secret=<secret_name_1> [--aws-secret=<secret_name_2>]
```
Of course, AWS credentials must be configured. See  https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/configuring-sdk.html

### Helm

```
helm repo add cert-exporter https://joe-elliott.github.io/cert-exporter/
helm repo update
helm upgrade --install cert-exporter cert-exporter/cert-exporter
```

### Dashboard

After running cert-exporter in your cluster it's easy to build a [custom dashboard](./docs/sample-dashboard.json) to expose information about the certs in your cluster.

![cert-exporter dashboard](./docs/dashboard.png)

### Exported Metrics

cert-exporter exports the following metrics

```
# HELP cert_exporter_error_total Cert Exporter Errors
# TYPE cert_exporter_build_info gauge
cert_exporter_build_info{branch="feat-add-build-info-metric",goarch="arm64",goos="darwin",goversion="go1.23.3",revision="7e7d2c6b1e757394375e3cd5918e61d37d3234bd",tags="unknown",version="2.17.0"} 1
# TYPE cert_exporter_error_total counter
cert_exporter_error_total 0
# HELP cert_exporter_discovered Cert Exporter Discovered Certificates
# TYPE cert_exporter_discovered gauge
cert_exporter_discovered 0
# HELP cert_exporter_cert_expires_in_seconds Number of seconds til the cert expires.
# TYPE cert_exporter_cert_expires_in_seconds gauge
cert_exporter_cert_expires_in_seconds{cn="client",filename="certsSibling/client.crt",issuer="root",nodename="master0"} 8.639964560021e+06
# HELP cert_exporter_kubeconfig_expires_in_seconds Number of seconds til the cert in kubeconfig expires.
# TYPE cert_exporter_kubeconfig_expires_in_seconds gauge
cert_exporter_kubeconfig_expires_in_seconds{cn="root",filename="kubeConfigSibling/kubeconfig",issuer="root",name="cluster1",nodename="master0",type="cluster"} 8.639964559682e+06
cert_exporter_kubeconfig_expires_in_seconds{cn="client",filename="kubeConfigSibling/kubeconfig",issuer="root",name="user1",nodename="master0",type="user"} 8.639964559249e+06
# HELP cert_exporter_secret_expires_in_seconds Number of seconds til the cert in the secret expires.
# TYPE cert_exporter_secret_expires_in_seconds gauge
cert_exporter_secret_expires_in_seconds{cn="example.com",issuer="example.com",key_name="ca.crt",secret_name="selfsigned-cert-tls",secret_namespace="cert-manager-test"} 8.6396867095666e+06
cert_exporter_secret_expires_in_seconds{cn="example.com",issuer="example.com",key_name="tls.crt",secret_name="selfsigned-cert-tls",secret_namespace="cert-manager-test"} 8.639686709417423e+06
# HELP certrequest_expires_in_seconds Number of seconds til the cert in the CertificateRequest expires.
# TYPE certrequest_expires_in_seconds gauge
cert_exporter_certrequest_expires_in_seconds{cert_request="example-crt-gn762",certrequest_namespace="cert-manager-test",cn="example.com",issuer="example.com"}
# HELP certrequest_not_after_timestamp Timestamp when the cert in the CertificateRequest expires.
# TYPE certrequest_not_after_timestamp gauge
cert_exporter_certrequest_not_after_timestamp{cert_request="example-crt-gn762",certrequest_namespace="cert-manager-test",cn="example.com",issuer="example.com"}
# HELP certrequest_not_before_timestamp Activation timestamp for cert in the certrequest.
# TYPE certrequest_not_before_timestamp gauge
cert_exporter_certrequest_not_before_timestamp{cert_request="example-crt-gn762",certrequest_namespace="cert-manager-test",cn="example.com",issuer="example.com"}
```

**cert_exporter_discovered**
The number of files matched by include/exclude globs across all file-based checkers (certificate files and kubeconfig files). Concurrent checkers accumulate into this gauge rather than overwriting it.

**cert_exporter_error_total**  
The total number of unexpected errors encountered by cert-exporter.  A good metric to watch to feel comfortable certs are being exported properly.

**`--cert-password-file` (optional)**  
File holding the password used to open password-protected certificate files found by `--include-cert-glob`, that is PKCS#12 (`.p12`, `.pfx`) and JKS keystores. A trailing newline is stripped, so `echo -n` is not required. The password is read from a file rather than taken as a flag value because process arguments are readable by anyone who can run `ps` on the host.

```
--include-cert-glob='/etc/pki/*.jks' --cert-password-file=/etc/cert-exporter/keystore-password
```

Only certificates are read out of a keystore, and a JKS keeps the certificate chain of a private key entry in the clear, so an entry whose key carries a password of its own is exported like any other. Certificates in Kubernetes secrets keep taking their password from the `password` key of the secret, unchanged.

The password applies to every file `--include-cert-glob` matches, so a password-less PKCS#12 in the same set will stop parsing once the flag is set; keep protected and unprotected keystores in separate globs. The file is read once at startup, which means a rotated password needs a restart. A JKS always needs its store password, even one holding nothing but trusted certificates.

Note that a keystore commonly holds several certificates sharing a `cn` and `issuer`, which Prometheus collapses into a single series. Enable `--include-serial-label` alongside this flag to keep them apart.

**`--include-serial-label` (optional)**  
Default **false** (no series identity change). When **true**, every certificate metric gains a `serial` label (lowercase hex). Enable this when a single file/secret/configmap key holds multiple PEMs that share the same `cn`/`issuer`, otherwise Prometheus collapses them into one series. Enabling this will cause churn, so check your dashboards and alerts beforehand.

Example with the flag on:

```
cert_exporter_secret_expires_in_seconds{cn="service-ca",issuer="service-ca",key_name="service-ca.crt",secret_name="…",secret_namespace="…",serial="a1b2c3"} …
cert_exporter_secret_expires_in_seconds{cn="service-ca",issuer="service-ca",key_name="service-ca.crt",secret_name="…",secret_namespace="…",serial="d4e5f6"} …
```

**cert_exporter_cert_expires_in_seconds**  
The number of seconds until a certificate stored in the PEM format is expired.  The `filename`, `issuer`, `cn`, and `nodename` labels indicate the exported cert (`serial` when enabled).

**cert_exporter_kubeconfig_expires_in_seconds**  
The number of seconds until a certificate stored in a kubeconfig expires.  The `filename`, `type`, `name`, and `nodename` labels indicate the kubeconfig, cluster or user node and name of the node (`serial` when enabled).  See details [here](https://kubernetes.io/docs/tasks/access-application-cluster/configure-access-multiple-clusters/).

**cert_exporter_secret_expires_in_seconds**
The number of seconds until a certificate stored in a kubernetes secret expires.  The `key_name`, `issuer`, `cn`, `secret_name`, and `secret_namespace` labels indicate the secret key, name and namespace (`serial` when enabled).

**cert_exporter_certrequest_expires_in_seconds**
The number of seconds until a certificate stored in a cert-manager CertificateRequest expires.  The `cert_request`, `issuer`, `cn`, and `certrequest_namespace` labels indicate the CertificateRequest, common name and namespace (`serial` when enabled).

**cert_exporter_certrequest_not_after_timestamp**
The timestamp when a certificate stored in a cert-manager CertificateRequest expires.   The `cert_request`, `issuer`, `cn`, and `certrequest_namespace` labels indicate the CertificateRequest, common name and namespace (`serial` when enabled).

**cert_exporter_certrequest_not_before_timestamp**
The timestamp when a certificate stored in a cert-manager CertificateRequest becomes valid.   The `cert_request`, `issuer`, `cn`, and `certrequest_namespace` labels indicate the CertificateRequest, common name and namespace (`serial` when enabled).



### Other Docs

- [Testing](./docs/testing.md)
  - An overview of the testing scripts and how to run them. It requires [kind](https://github.com/kubernetes-sigs/kind) CLI.
- [Deployment](./docs/deploy.md)
  - Information on how to deploy cert-exporter as well as examples for a kops cluster.
- [Daemonset for Prometheus-operator](./docs/daemonset-prom-operator.yaml)
  - How to deploy daemonset+service+servicemonitor+dashboard if you use [prometheus-operator](https://github.com/coreos/prometheus-operator) into the `monitoring` namespace
