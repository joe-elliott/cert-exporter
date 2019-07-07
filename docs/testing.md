# testing

cert-exporter testing is fairly simple.  The [./test.sh](../test/test.sh) in the test directory will build the application, generate some certs and kubeconfigs, run the application against the files and curl the prometheus metrics to confirm they are accurate.  It takes one parameter which is the number of days to expire the test certs in.

Example:

```
# ./test.sh
** Testing Certs and kubeconfig in the same dir
cert_exporter_error_total 0
TEST SUCCESS: cert_exporter_cert_expires_in_seconds{filename="certs/client.crt"}
TEST SUCCESS: cert_exporter_cert_expires_in_seconds{filename="certs/root.crt"}
TEST SUCCESS: cert_exporter_cert_expires_in_seconds{filename="certs/server.crt"}
TEST SUCCESS: cert_exporter_kubeconfig_expires_in_seconds{filename="certs/kubeconfig",name="cluster1",type="cluster"}
TEST SUCCESS: cert_exporter_kubeconfig_expires_in_seconds{filename="certs/kubeconfig",name="cluster2",type="cluster"}
TEST SUCCESS: cert_exporter_kubeconfig_expires_in_seconds{filename="certs/kubeconfig",name="user1",type="user"}
TEST SUCCESS: cert_exporter_kubeconfig_expires_in_seconds{filename="certs/kubeconfig",name="user2",type="user"}
** Testing Certs and kubeconfig in sibling dirs
cert_exporter_error_total 0
TEST SUCCESS: cert_exporter_cert_expires_in_seconds{filename="certsSibling/client.crt"}
TEST SUCCESS: cert_exporter_cert_expires_in_seconds{filename="certsSibling/root.crt"}
TEST SUCCESS: cert_exporter_cert_expires_in_seconds{filename="certsSibling/server.crt"}
TEST SUCCESS: cert_exporter_kubeconfig_expires_in_seconds{filename="kubeConfigSibling/kubeconfig",name="cluster1",type="cluster"}
TEST SUCCESS: cert_exporter_kubeconfig_expires_in_seconds{filename="kubeConfigSibling/kubeconfig",name="cluster2",type="cluster"}
TEST SUCCESS: cert_exporter_kubeconfig_expires_in_seconds{filename="kubeConfigSibling/kubeconfig",name="user1",type="user"}
TEST SUCCESS: cert_exporter_kubeconfig_expires_in_seconds{filename="kubeConfigSibling/kubeconfig",name="user2",type="user"}
** Testing Error metric increments
E0707 09:25:59.470115   56712 periodicCertChecker.go:47] Error on certs/client.crt: Failed to parse as a pem
cert_exporter_error_total 1
# ./testCleanup.sh
```

It's not great, but it gets the job done.  There could definitely be some work put into this.

### Dependencies

- bash
- openssl
- curl