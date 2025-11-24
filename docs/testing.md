# Testing

cert-exporter uses Go's built-in testing framework for all tests.

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

### Integration Tests

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
