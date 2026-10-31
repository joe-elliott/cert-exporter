# Deployment

cert-exporter can easily be deployed using [this container](https://hub.docker.com/r/joeelliott/cert-exporter) to a cluster to export cert expiry information to prometheus using a Daemonset.  A daemonset was chosen because cert information should exist on every node and master in your cluster.

**WARNING** If you run this application in your cluster it will probably require elevated privileges of some kind.  Additionally you are exposing VERY sensitive information to it.  Review the source!

### kops

We use kops to manage our Kubernetes clusters and the following two daemonsets cover our nodes and masters.  We use two daemonsets because the certs on a master and node are very different.  These daemonset specs were built on a cluster built with kops 1.12.

The following configurations will not only export the certificates used to govern access between Kubernetes components, but etcd as well.

- [masters](./kops-masters.yaml)
- [nodes](./kops-nodes.yaml)

Note that certs are often restricted files.  Running as root allows the application to access them on the host:

```
  securityContext:
    runAsUser: 0
```

### cert-manager

cert-exporter also supports certificates stored in Kubernetes secrets and configmaps.  In this case it expects the secret/configmap to be in the PEM format.  See the [deployment yaml](./cert-manager.yaml) for an example deployment that will find and export all cert-manager certificates.  Note that it comes with the appropriate RBAC objects to allow the application to read certs.

**cert-manager.io/v1**
`--secrets-annotation-selector=cert-manager.io/certificate-name`

### flags
These are all the flags cert-exporter accepts, as printed by `--help`.  The glob flags include and exclude certs and kubeconfig files; the selector and namespace flags pick the Kubernetes objects to check.

```
  -aws-account string
    	AWS account to search for secrets in
  -aws-key-substring string
    	Substring to search for in the key name. Matched keys are parsed as certs. (default ".pem")
  -aws-region string
    	AWS region to search for secrets in
  -aws-secret value
    	AWS secrets to export
  -certrequests-annotation-selector value
    	Annotation selector to find certrequests to publish as metrics.
  -certrequests-label-selector value
    	Label selector to find certrequests to publish as metrics.
  -certrequests-namespace string
    	Kubernetes namespace to list certrequests.
  -certrequests-namespaces string
    	Kubernetes comma-delimited list of namespaces to search for certrequests.
  -configmaps-annotation-selector value
    	Annotation selector to find configmaps to publish as metrics.
  -configmaps-exclude-glob value
    	Configmap globs to exclude when looking for configmap data keys.
  -configmaps-include-glob value
    	Configmap globs to include when looking for configmap data keys (Default "*").
  -configmaps-label-selector value
    	Label selector to find configmaps to publish as metrics.
  -configmaps-namespace string # (Deprecated) Use `-configmaps-namespaces`.
    	Kubernetes namespace to list configmaps.
  -configmaps-namespace-label-selector value
    	Label selector to find namespaces in which to find configmaps to publish as metrics.
  -configmaps-namespaces string
    	Kubernetes comma-delimited list of namespaces to search for configmaps.
  -enable-certrequests-check
    	Enable certrequests check.
  -enable-webhook-cert-check
    	Enable webhook cert check.
  -exclude-cert-glob value
    	File globs to exclude when looking for certs.
  -exclude-kubeconfig-glob value
    	File globs to exclude when looking for kubeconfigs.
  -include-cert-glob value
    	File globs to include when looking for certs.
  -include-kubeconfig-glob value
    	File globs to include when looking for kubeconfigs.
  -include-serial-label
    	Add serial label to certificate metrics (disambiguates multi-PEM bundles).
  -kubeconfig string
    	Path to a kubeconfig. Only required if out-of-cluster.
  -logtostderr
    	DEPRECATED: This flag is no longer used. Logs are always written to stderr. (default true)
  -polling-period duration
    	Periodic interval in which to check certs. (default 1h0m0s)
  -prometheus-disable-exporter-metrics
    	Exclude metrics about the exporter itself (promhttp_*, process_*, go_*).
  -prometheus-listen-address string
    	The address to listen on for Prometheus scrapes. (default ":8080")
  -prometheus-path string
    	The path to publish Prometheus metrics to. (default "/metrics")
  -secret-include-types value
    	Select only specific a secret type (Default nil).
  -secrets-annotation-selector value
    	Annotation selector to find secrets to publish as metrics.
  -secrets-exclude-glob value
    	Secret globs to exclude when looking for secret data keys.
  -secrets-include-glob value
    	Secret globs to include when looking for secret data keys (Default "*").
  -secrets-label-selector value
    	Label selector to find secrets to publish as metrics.
  -secrets-namespace string # (Deprecated) Use `-secrets-namespaces`.
    	Kubernetes namespace to list secrets.
  -secrets-namespace-label-selector value
    	Label selector to find namespaces in which to find secrets to publish as metrics.
  -secrets-namespaces string
    	Kubernetes comma-delimited list of namespaces to search for secrets.
  -webhooks-annotation-selector value
    	Annotation selector to find webhooks to publish as metrics.
  -webhooks-label-selector value
    	Label selector to find webhooks to publish as metrics.
```

### profiling

cert-exporter includes Go's built-in pprof profiling endpoints to help diagnose performance and memory issues. The following profiling endpoints are available on the same port as Prometheus metrics:

- `/debug/pprof/` - Index page with available profiles
- `/debug/pprof/heap` - Memory allocation profile
- `/debug/pprof/goroutine` - Stack traces of all current goroutines
- `/debug/pprof/threadcreate` - Stack traces that led to creation of new OS threads
- `/debug/pprof/block` - Stack traces that led to blocking on synchronization primitives
- `/debug/pprof/mutex` - Stack traces of holders of contended mutexes
- `/debug/pprof/profile` - CPU profile (30-second sample by default)

Example usage to capture a heap profile for memory leak investigation:

```bash
# Port-forward to the cert-exporter pod
kubectl port-forward <pod-name> 8080:8080

# Capture heap profile
curl http://localhost:8080/debug/pprof/heap > heap.prof

# Analyze with pprof
go tool pprof heap.prof
```

For detailed profiling documentation, see the [Go pprof documentation](https://pkg.go.dev/net/http/pprof).

### environment variables

cert-exporter respects the `NODE_NAME` environment variable.  If present it will add this value as label to file metrics.  See one of the [deployment yamls](./kops-nodes.yaml) for an example of using the [Kubernetes Downward API](https://kubernetes.io/docs/tasks/inject-data-application/downward-api-volume-expose-pod-information/) to make use of this feature.

### AWS

cert-exporter is able to check secrets in AWS Secret Manager. The following arguments exist for monitoring certificates in AWS Secret Manager:

```
  -aws-account string
        AWS account to search for secrets in
  -aws-key-substring string
        Substring to search for in the key name. Matched keys are parsed as certs. (default ".pem")
  -aws-region string
        AWS region to search for secrets in
  -aws-secret value
        AWS secrets to export
```

Multiple `-aws-secret` arguments can be provided to monitor more than 1 secret. Example of 2 possible cases when using AWS Secret Manager:

```json
{
    "tls.pem": "-----BEGIN CERTIFICATE-----\nMIID7TCCAtWgAwIBAgIUUC0QZlGksaxYSfvF7RoC9O44VYEwDQYJKoZIhvcNAQEL\n...\n-----END CERTIFICATE-----",
    "tls.key": "-----BEGIN PRIVATE KEY-----\nMIIFNTBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQwlrvimumxjmK50ne\n...\n-----END PRIVATE KEY-----",
}
```

or the values to be base64 encoded:

```json
{
    "tls.pem": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUQ3VENDQXRXZ0F3SUJBZ0lVVUMwUVpsR2tzYXhZU2Z2RjdSb0M5TzQ0VllFd0RRWUpLb1pJaHZjTkFRRUw...",
    "tls.key": "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tXE1JSUZOVEJmQmdrcWhraUc5dzBCQlEwd1VqQXhCZ2txaGtpRzl3MEJCUXd3SkFRUXdscnZpbXVteGptSzUwbmU...",
}
```
