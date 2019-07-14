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

WIP

### flags
The following 7 flags are the most commonly used to control cert-exporter behavior.  They allow you to use file globs to include and exclude certs and kubeconfig files.  

```
  -exclude-cert-glob value
    	File globs to exclude when looking for certs.
  -exclude-kubeconfig-glob value
    	File globs to exclude when looking for kubeconfigs.
  -include-cert-glob value
    	File globs to include when looking for certs.
  -include-kubeconfig-glob value
    	File globs to include when looking for kubeconfigs.
  -secrets-data-glob string
    	Glob to match against secret data keys. (default "*.crt")
  -secrets-label-selector value
    	Label selector to find secrets to publish as metrics.
  -polling-period duration
    	Periodic interval in which to check certs. (default 1h0m0s)
```

For a full flag listing run the application with the `--help` parameter.
