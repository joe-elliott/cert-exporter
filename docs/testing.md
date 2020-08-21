# Testing

cert-exporter testing is fairly simple.  The [./test.sh](../test/files/test.sh) in the test directory will generate some certs and kubeconfigs, run the application against the files and curl the prometheus metrics to confirm they are accurate.  It takes one parameter which is the number of days to expire the test certs in.

Example:

```
# ./test.sh
** Testing Certs and kubeconfig in the same dir
cert_exporter_error_total 0
TEST SUCCESS: cert_exporter_cert_expires_in_seconds{filename="certs/client.crt",issuer="root",nodename="master0"}
TEST SUCCESS: cert_exporter_cert_expires_in_seconds{filename="certs/root.crt",issuer="root",nodename="master0"}
TEST SUCCESS: cert_exporter_cert_expires_in_seconds{filename="certs/server.crt",issuer="root",nodename="master0"}
TEST SUCCESS: cert_exporter_kubeconfig_expires_in_seconds{filename="certs/kubeconfig",name="cluster1",nodename="master0",type="cluster"}
TEST SUCCESS: cert_exporter_kubeconfig_expires_in_seconds{filename="certs/kubeconfig",name="cluster2",nodename="master0",type="cluster"}
TEST SUCCESS: cert_exporter_kubeconfig_expires_in_seconds{filename="certs/kubeconfig",name="user1",nodename="master0",type="user"}
TEST SUCCESS: cert_exporter_kubeconfig_expires_in_seconds{filename="certs/kubeconfig",name="user2",nodename="master0",type="user"}
** Testing Certs and kubeconfig in sibling dirs
cert_exporter_error_total 0
TEST SUCCESS: cert_exporter_cert_expires_in_seconds{filename="certsSibling/client.crt",issuer="root",nodename="master0"}
TEST SUCCESS: cert_exporter_cert_expires_in_seconds{filename="certsSibling/root.crt",issuer="root",nodename="master0"}
TEST SUCCESS: cert_exporter_cert_expires_in_seconds{filename="certsSibling/server.crt",issuer="root",nodename="master0"}
TEST SUCCESS: cert_exporter_kubeconfig_expires_in_seconds{filename="kubeConfigSibling/kubeconfig",name="cluster1",nodename="master0",type="cluster"}
TEST SUCCESS: cert_exporter_kubeconfig_expires_in_seconds{filename="kubeConfigSibling/kubeconfig",name="cluster2",nodename="master0",type="cluster"}
TEST SUCCESS: cert_exporter_kubeconfig_expires_in_seconds{filename="kubeConfigSibling/kubeconfig",name="user1",nodename="master0",type="user"}
TEST SUCCESS: cert_exporter_kubeconfig_expires_in_seconds{filename="kubeConfigSibling/kubeconfig",name="user2",nodename="master0",type="user"}
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

### cert-manager testing

`./test/cert-manager-v1alpha1/test.sh` and `./test/cert-manager-v1alpha2/test.sh` do really basic testing of cert-manager created certs.
