# Custom Secrets Monitoring

If you have custom secrets you wish to monitor (you created them as k8s resources), the examples in this directory will help you achieve that.

## Service Definition

There is a service defined in [service.yaml](https://github.com/hakhundov/cert-exporter/blob/master/docs/examples/custom-secrets/service.yaml) which is used by prometheus service monitor with the config in [service-monitor.yaml](https://github.com/hakhundov/cert-exporter/blob/master/docs/examples/custom-secrets/service-monitor.yaml).  The prometheus config assumes you are using the [prometheus-operator helm chart](https://github.com/helm/charts/tree/master/stable/prometheus-operator)

## Secret Creation

On [line 27 of the deployment file](https://github.com/hakhundov/cert-exporter/blob/master/docs/examples/custom-secrets/deployment.yaml#L27) you will see the additional options passed to the cert exporter that allows for monitoring certificates based on labels.  The [example secret](https://github.com/hakhundov/cert-exporter/blob/master/docs/examples/custom-secrets/secret.yaml) is configured to be monitored by prometheus.

**NOTE:  The label only has to have a matching key.  Any value supplied will work!**

## Troubleshooting

### The certificate dashboard does not show anything

By default, the certificate dashboard monitors for `cert_exporter_cert_expires_in_seconds` and `cert_exporter_kubeconfig_expires_in_seconds`.  To have it monitor for secrets, you need to add/change to check `cert_exporter_secret_expires_in_seconds`.

### The metrics are not showing up in Prometheus

There could be a number of things wrong, but [this helpful flowchart](https://learnk8s.io/a/troubleshooting-kubernetes.pdf) will help to get you sorted.

You can also `exec` into a pod running in your cluster and try to curl the metrics endpoint of the `cert-exporter` by running `curl cert-exporter:8080/metrics` and see what you get back. (`cert-exporter` hostname assumes that is the name you have used in [service.yaml](https://github.com/hakhundov/cert-exporter/blob/master/docs/examples/custom-secrets/service.yaml))
