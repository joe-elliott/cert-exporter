# deploy

wip

#### flags
The following 5 flags are the most commonly used to control cert-exporter behavior.  They allow you to use file globs to include and exclude certs and kubeconfig files.  

```
  -exclude-cert-glob value
    	File globs to exclude when looking for certs.
  -exclude-kubeconfig-glob value
    	File globs to exclude when looking for kubeconfigs.
  -include-cert-glob value
    	File globs to include when looking for certs.
  -include-kubeconfig-glob value
    	File globs to include when looking for kubeconfigs.
  -polling-period duration
    	Periodic interval in which to check certs. (default 1h0m0s)
```

For a full flag listing run the application with the `--help` parameter.
