package exporters

import (
	"encoding/pem"
	"testing"

	"github.com/joe-elliott/cert-exporter/internal/testutil"
)

func TestParseAsPEM(t *testing.T) {
	const certCN = "cert"
	cert := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName: certCN,
		Days:       90,
		IsCA:       false,
	})
	const rootCN = "root-cert"
	root := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName: rootCN,
		Days:       365,
		IsCA:       true,
	})
	const intermediateCN = "intermediate-cert"
	intermediate := testutil.GenerateSignedCertificate(t, testutil.CertConfig{
		CommonName: intermediateCN,
		Days:       180,
		IsCA:       false,
	}, root)

	tests := []struct {
		name         string
		setupFunc    func(t *testing.T) []byte
		wantParsed   bool
		wantMetrics  int
		wantErr      bool
		validateFunc func(t *testing.T, metrics []certMetric)
	}{
		{
			name: "valid single certificate",
			setupFunc: func(t *testing.T) []byte {
				return cert.CertPEM
			},
			wantParsed:  true,
			wantMetrics: 1,
			wantErr:     false,
			validateFunc: func(t *testing.T, metrics []certMetric) {
				if metrics[0].cn != certCN {
					t.Errorf("Expected CN '%s', got '%s'", certCN, metrics[0].cn)
				}
				if metrics[0].durationUntilExpiry <= 0 {
					t.Errorf("Expected positive duration until expiry, got %f", metrics[0].durationUntilExpiry)
				}
			},
		},
		{
			name: "valid certificate chain",
			setupFunc: func(t *testing.T) []byte {
				return testutil.CreateCertBundle(intermediate, root)
			},
			wantParsed:  true,
			wantMetrics: 2,
			wantErr:     false,
			validateFunc: func(t *testing.T, metrics []certMetric) {
				if metrics[0].cn != intermediateCN {
					t.Errorf("Expected first cert CN '%s', got '%s'", intermediateCN, metrics[0].cn)
				}
				if metrics[1].cn != rootCN {
					t.Errorf("Expected second cert CN '%s', got '%s'", rootCN, metrics[1].cn)
				}
			},
		},
		{
			name: "certificate and chain with whitespaces",
			setupFunc: func(t *testing.T) []byte {
				// Combine and add whitespaces.
				combined := append(cert.CertPEM, []byte("   \n\t  \n")...)
				combined = append(combined, intermediate.CertPEM...)
				combined = append(combined, []byte("\n\n")...)
				combined = append(combined, root.CertPEM...)
				combined = append(combined, []byte("\n\t\t\n")...)
				return combined
			},
			wantParsed:  true,
			wantMetrics: 3,
			wantErr:     false,
		},
		{
			name: "certificate with private key and chain (should only parse certificates)",
			setupFunc: func(t *testing.T) []byte {
				// Combine cert and key.
				combined := append(cert.CertPEM, cert.PrivateKeyPEM...)
				// And the chain.
				combined = append(combined, intermediate.CertPEM...)
				combined = append(combined, root.CertPEM...)
				return combined
			},
			wantParsed:  true,
			wantMetrics: 3, // Should only parse the certificate, not the key.
			wantErr:     false,
		},
		{
			name: "certificate with private key (on first place) and chain (should only parse certificates)",
			setupFunc: func(t *testing.T) []byte {
				// Combine cert and key.
				combined := append(cert.PrivateKeyPEM, cert.CertPEM...)
				// And the chain.
				combined = append(combined, intermediate.CertPEM...)
				combined = append(combined, root.CertPEM...)
				return combined
			},
			wantParsed:  true,
			wantMetrics: 3, // Should only parse the certificate, not the key.
			wantErr:     false,
		},
		{
			name: "invalid PEM data",
			setupFunc: func(t *testing.T) []byte {
				return []byte("this is not a valid PEM certificate")
			},
			wantParsed:  false,
			wantMetrics: 0,
			wantErr:     true,
		},
		{
			name: "empty input",
			setupFunc: func(t *testing.T) []byte {
				return []byte("")
			},
			wantParsed:  false,
			wantMetrics: 0,
			wantErr:     true,
		},
		{
			name: "only private key (no certificate)",
			setupFunc: func(t *testing.T) []byte {
				return cert.PrivateKeyPEM
			},
			wantParsed:  true,
			wantMetrics: 0, // No certificates, only key.
			wantErr:     false,
		},
		{
			name: "corrupted certificate data",
			setupFunc: func(t *testing.T) []byte {
				// Create a PEM block with invalid certificate data.
				block := &pem.Block{
					Type:  "CERTIFICATE",
					Bytes: []byte("invalid certificate data"),
				}
				return pem.EncodeToMemory(block)
			},
			wantParsed:  true,
			wantMetrics: 0,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certBytes := tt.setupFunc(t)
			parsed, metrics, err := parseAsPEM(certBytes)

			if parsed != tt.wantParsed {
				t.Errorf("parseAsPEM() parsed = %v, want %v", parsed, tt.wantParsed)
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("parseAsPEM() error = %v, wantErr %v", err, tt.wantErr)
			}

			if len(metrics) != tt.wantMetrics {
				t.Errorf("parseAsPEM() returned %d metrics, want %d", len(metrics), tt.wantMetrics)
			}

			// Validate metrics if validation function is provided.
			if tt.validateFunc != nil && len(metrics) > 0 {
				tt.validateFunc(t, metrics)
			}

			// Validate common metric properties if we have metrics.
			if len(metrics) > 0 && !tt.wantErr {
				for i, metric := range metrics {
					if metric.notBefore == 0 {
						t.Errorf("metric[%d] notBefore should not be zero", i)
					}
					if metric.notAfter == 0 {
						t.Errorf("metric[%d] notAfter should not be zero", i)
					}
				}
			}
		})
	}
}
