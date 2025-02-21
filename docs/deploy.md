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
The following 17 flags are the most commonly used to control cert-exporter behavior.  They allow you to use file globs to include and exclude certs and kubeconfig files.

```
  -exclude-cert-glob value
    	File globs to exclude when looking for certs.
  -exclude-kubeconfig-glob value
    	File globs to exclude when looking for kubeconfigs.
  -include-cert-glob value
    	File globs to include when looking for certs.
  -include-kubeconfig-glob value
    	File globs to include when looking for kubeconfigs.
  -secrets-annotation-selector string
    	Annotation selector to find secrets to publish as metrics.
  -secrets-exclude-glob value
    	Globs to match against secret data keys.
  -secrets-include-glob value
    	Globs to match against secret data keys (Default "*").
  -secrets-label-selector value
    	Label selector to find secrets to publish as metrics.
  -secrets-namespace string # (Deprecated) Use `-secrets-namespaces`.
    	Kubernetes namespace to list secrets.
  -secrets-namespaces string
        Kubernetes comma-delimited list of namespaces to search for secrets.
  -secrets-namespace-label-selector value
        Label selector to find namespaces in which to find secrets to publish as metrics.
  -configmaps-annotation-selector string
    	Annotation selector to find configmaps to publish as metrics.
  -configmaps-exclude-glob value
    	Globs to match against configmap data keys.
  -configmaps-include-glob value
    	Globs to match against configmap data keys (Default "*").
  -configmaps-label-selector value
    	Label selector to find configmaps to publish as metrics.
  -configmaps-namespace string # (Deprecated) Use `-configmaps-namespaces`.
    	Kubernetes namespace to list configmaps.
  -configmaps-namespaces
        Kubernetes comma-delimited list of namespaces to search for configmaps.
  -configmaps-namespace-label-selector value
        Label selector to find namespaces in which to find configmaps to publish as metrics.
  -enable-webhook-cert-check bool
        Enable webhook client config CABundle cert check (Default "false").
  -webhooks-label-selector
        Label selector to find webhooks to publish as metrics.
  -webhooks-annotation-selector
        Annotation selector to find webhooks to publish as metrics.
  -polling-period duration
    	Periodic interval in which to check certs. (default 1h0m0s)
```

For a full flag listing run the application with the `--help` parameter.

### environment variables

cert-exporter respects the `NODE_NAME` environment variable.  If present it will add this value as label to file metrics.  See one of the [deployment yamls](./kops-nodes.yaml) for an example of using the [Kubernetes Downward API](https://kubernetes.io/docs/tasks/inject-data-application/downward-api-volume-expose-pod-information/) to make use of this feature.
