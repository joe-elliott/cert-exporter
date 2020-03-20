# Local Secrets Monitoring

If you have local secrets you wish to monitor, the examples in this directory will help you acheive that.

## Service Definition

There is a service defined in [service.yaml](https://github.com/joe-elliott/cert-exporter/blob/master/docs/examples/local-secrets/service.yaml) to allow you to scrape the exporter from prometheus with the config in [prometheus-scrape.yaml](https://github.com/joe-elliott/cert-exporter/blob/master/docs/examples/local-secrets/prometheus-scrape.yaml).  The prometheus config assumes you are using the [prometheus-operator helm chart](https://github.com/helm/charts/tree/master/stable/prometheus-operator)

## Secret Creation

On [line 27 of the deployment file](https://github.com/joe-elliott/cert-exporter/blob/master/docs/examples/local-secrets/deployment.yaml#27) you will see the additional options passed to the cert exporter that allows for monitoring certificates based on labels.  In order for your certs to be monitored, the certificate keys all need to end in `*.crt` (unless you override that option with --secrets-data-glob).  The [example secret](https://github.com/joe-elliott/cert-exporter/blob/master/docs/examples/local-secrets/secret.yaml) is configured to be monitored by prometheus.

**NOTE:  The label only has to have a matching key.  Any value supplied will work!**

## Troubleshooting

### The certificate dashboard does not show anything

By default, the certificate dashboard monitors for `cert_exporter_cert_expires_in_seconds` and `cert_exporter_kubeconfig_expires_in_seconds`.  To have it monitor for secrets, you need to add/change to check `cert_exporter_secret_expires_in_seconds`.

### The metrics are not showing up in Prometheus

There could be a number of things wrong, but [this helpful flowchart](https://learnk8s.io/a/troubleshooting-kubernetes.pdf) will help to get you sorted.

You can also `exec` into a pod running in your cluster and try to curl the metrics endpoint of the `cert-exporter` by running `curl cert-exporter:8080/metrics` and see what you get back.