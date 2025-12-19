# Testing

cert-exporter uses both Go's built-in testing framework for unit tests and bash scripts for end-to-end integration testing.

## Running Tests

### Unit Tests

Run all unit tests with:

```bash
make test
```

Or directly with Go:

```bash
go test -v -race ./...
```

Unit tests cover:
- Certificate parsing (PEM and PKCS12 formats)
- Certificate exporter functionality
- Kubeconfig parsing and certificate extraction
- File-based certificate checking
- Metric generation and labels
- Error handling

### Integration Tests (Go)

Integration tests require a Kubernetes cluster with KUBECONFIG set:

```bash
make test-integration
```

Or directly with Go:

```bash
go test -v -tags=integration ./integration_test.go
```

Integration tests cover:
- End-to-end certificate monitoring
- Kubernetes secret checking
- ConfigMap certificate extraction
- Real Prometheus metric collection

### Integration Tests (Bash)

#### File-based Certificate Testing

The [test/files/test.sh](../test/files/test.sh) script generates test certificates and kubeconfigs, runs the application against the files, and curls the prometheus metrics to confirm they are accurate. It takes one parameter which is the number of days to expire the test certs in.

Example:

```bash
cd test/files
./test.sh 100
```

Output:
```
** Testing Certs and kubeconfig in the same dir
cert_exporter_error_total 0
TEST SUCCESS: cert_exporter_cert_expires_in_seconds{filename="certs/client.crt",issuer="root",nodename="master0"}
TEST SUCCESS: cert_exporter_cert_expires_in_seconds{filename="certs/root.crt",issuer="root",nodename="master0"}
TEST SUCCESS: cert_exporter_cert_expires_in_seconds{filename="certs/server.crt",issuer="root",nodename="master0"}
TEST SUCCESS: cert_exporter_kubeconfig_expires_in_seconds{filename="certs/kubeconfig",name="cluster1",nodename="master0",type="cluster"}
...
```

Dependencies:
- bash
- openssl
- curl

#### cert-manager Testing

The [test/cert-manager/test.sh](../test/cert-manager/test.sh) script does basic testing of cert-manager created certificates in a Kubernetes cluster.

Requirements:
- kind (Kubernetes in Docker)
- kubectl
- A built cert-exporter binary

Example:

```bash
cd test/cert-manager
./test.sh
```

This will:
1. Create a kind cluster
2. Install cert-manager
3. Create test certificates, secrets, configmaps, and webhooks
4. Run cert-exporter against these resources
5. Validate the exported metrics
6. Clean up the cluster

### All Tests

Run both unit and integration tests:

```bash
make test-all
```

## Test Coverage

Generate a coverage report:

```bash
go test -coverprofile=coverage.txt -covermode=atomic ./...
go tool cover -html=coverage.txt
```

## Test Organization

- **Unit tests**: Located alongside source files (e.g., `certExporter_test.go`)
- **Integration tests**: Located in `integration_test.go` at the root
- **Test utilities**: Located in `internal/testutil/`
  - `certs.go` - Certificate generation helpers
  - `kubeconfig.go` - Kubeconfig file builders

## Writing Tests

When adding new functionality:

1. Add unit tests for individual components
2. Add integration tests for end-to-end flows
3. Ensure tests use the test utilities in `internal/testutil/`
4. Use `t.TempDir()` for temporary files
5. Initialize metrics with `metrics.Init(true)` to avoid conflicts

### Example Unit Test

```go
func TestCertExporter_ExportMetrics(t *testing.T) {
    metrics.Init(true)

    tmpDir := testutil.CreateTempCertDir(t)
    certFile := filepath.Join(tmpDir, "test.crt")

    cert := testutil.GenerateCertificate(t, testutil.CertConfig{
        CommonName:   "test-cert",
        Organization: "test-org",
        Country:      "US",
        Province:     "CA",
        Days:         30,
    })

    testutil.WriteCertToFile(t, cert.CertPEM, certFile)

    exporter := &CertExporter{}
    err := exporter.ExportMetrics(certFile, "test-node")

    if err != nil {
        t.Fatalf("ExportMetrics() failed: %v", err)
    }

    // Verify metrics...
}
```

## Continuous Integration

Tests run automatically in GitHub Actions on:
- Pull requests
- Pushes to master
- Tag releases

The CI pipeline runs both unit and integration tests to ensure quality.
