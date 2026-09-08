package exporters

import (
	"encoding/pem"
	"strings"
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
					if metric.serial == "" {
						t.Errorf("metric[%d] serial should not be empty", i)
					}
				}
			}
		})
	}
}

func TestMatchGlobs(t *testing.T) {
	tests := []struct {
		name  string
		input string
		globs []string
		want  bool
	}{
		{name: "exact match", input: "test-cert", globs: []string{"test-cert"}, want: true},
		{name: "wildcard match", input: "my-service.example.com", globs: []string{"*.example.com"}, want: true},
		{name: "wildcard is not a DNS wildcard", input: "a.b.example.com", globs: []string{"*.example.com"}, want: true},
		{name: "no match", input: "other-service.internal", globs: []string{"*.example.com"}, want: false},
		{name: "multiple globs - first matches", input: "test-ca", globs: []string{"test-*", "prod-*"}, want: true},
		{name: "multiple globs - second matches", input: "prod-ca", globs: []string{"test-*", "prod-*"}, want: true},
		{name: "multiple globs - none match", input: "staging-ca", globs: []string{"test-*", "prod-*"}, want: false},
		{name: "empty glob list - no match", input: "anything", globs: []string{}, want: false},
		{name: "question mark wildcard", input: "cert-a", globs: []string{"cert-?"}, want: true},
		{name: "character class", input: "cert-1", globs: []string{"cert-[0-9]"}, want: true},

		// CNs are not paths: a slash must not stop a wildcard. URI-style names
		// (SPIFFE IDs, OpenSSL-style names) contain slashes.
		{name: "star matches a URI CN", input: "spiffe://cluster.local/ns/foo", globs: []string{"*"}, want: true},
		{name: "doublestar matches a URI CN", input: "spiffe://cluster.local/ns/foo", globs: []string{"**"}, want: true},
		{name: "star crosses slashes mid-pattern", input: "spiffe://cluster.local/ns/foo", globs: []string{"spiffe://*"}, want: true},
		{name: "star matches inside a URI CN", input: "spiffe://cluster.local/ns/foo", globs: []string{"*cluster*"}, want: true},
		{name: "prefix glob on a URI CN", input: "spiffe://cluster.local/ns/foo", globs: []string{"spiffe://cluster.local/ns/*"}, want: true},
		{name: "non-matching glob on a URI CN", input: "spiffe://cluster.local/ns/foo", globs: []string{"spiffe://other.local/*"}, want: false},
		{name: "slash in an OpenSSL style name", input: "/CN=web/O=Acme", globs: []string{"*O=Acme"}, want: true},
		{name: "question mark matches a slash", input: "/", globs: []string{"?"}, want: true},

		// Braces are metacharacters, which is a change from filepath.Match.
		{name: "alternation", input: "prod-ca", globs: []string{"{test,prod}-ca"}, want: true},
		{name: "alternation with a single star branch matches everything", input: "web.example.com", globs: []string{"{*}"}, want: true},
		{name: "unescaped braces are not literal", input: "{a,b}", globs: []string{"{a,b}"}, want: false},
		{name: "escaped braces are literal", input: "{a}", globs: []string{`\{a\}`}, want: true},

		// A cert with no CN is matched only by a pattern that matches "".
		{name: "empty string with non-star glob - no match", input: "", globs: []string{"test-*"}, want: false},
		{name: "empty string with question mark - no match", input: "", globs: []string{"?"}, want: false},
		{name: "empty string with character class - no match", input: "", globs: []string{"[a-z]"}, want: false},
		{name: "empty string with star glob - matches", input: "", globs: []string{"*"}, want: true},
		{name: "empty string with doublestar glob - matches", input: "", globs: []string{"**"}, want: true},
		{name: "empty string with empty pattern - matches", input: "", globs: []string{""}, want: true},
		{name: "empty string with empty alternation branch - matches", input: "", globs: []string{"{,internal}"}, want: true},

		// A "/"-bearing pattern must not match a NUL-bearing CN, which Go will
		// happily decode out of a UTF8String.
		{name: "slash pattern does not match a NUL in the CN", input: "a\x00b", globs: []string{"a/b"}, want: false},
		{name: "slash pattern matches an actual slash", input: "a/b", globs: []string{"a/b"}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchGlobs(tt.input, tt.globs)
			if got != tt.want {
				t.Errorf("matchGlobs(%q, %v) = %v, want %v", tt.input, tt.globs, got, tt.want)
			}
		})
	}
}

func TestValidateCertGlobs(t *testing.T) {
	tests := []struct {
		name    string
		globs   []string
		wantErr bool
	}{
		{name: "no globs", globs: nil},
		{name: "plain name", globs: []string{"web.example.com"}},
		{name: "wildcard", globs: []string{"*"}},
		{name: "doublestar", globs: []string{"**"}},
		{name: "character class", globs: []string{"cert-[0-9]"}},
		{name: "alternation", globs: []string{"{test,prod}-ca"}},
		{name: "escaped braces", globs: []string{`\{a\}`}},
		{name: "uri style", globs: []string{"spiffe://cluster.local/ns/*"}},
		{name: "unterminated character class", globs: []string{"cert-["}, wantErr: true},
		{name: "unterminated alternation", globs: []string{"{a"}, wantErr: true},
		{name: "unescaped closing brace", globs: []string{"a}b"}, wantErr: true},
		{name: "unterminated class among valid patterns", globs: []string{"cert-*", "cert-["}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCertGlobs(tt.globs)
			if tt.wantErr && err == nil {
				t.Errorf("ValidateCertGlobs(%v) = nil, want an error", tt.globs)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidateCertGlobs(%v) = %v, want nil", tt.globs, err)
			}
		})
	}
}

// The startup error is the operator's only clue about which flag value is
// wrong, so it has to name the offending pattern.
func TestValidateCertGlobsErrorNamesThePattern(t *testing.T) {
	err := ValidateCertGlobs([]string{"cert-*", "cert-["})
	if err == nil {
		t.Fatal("ValidateCertGlobs() = nil, want an error")
	}
	if !strings.Contains(err.Error(), "cert-[") {
		t.Errorf("error %q does not name the offending pattern %q", err, "cert-[")
	}
}

func TestFilterMetrics(t *testing.T) {
	inputMetrics := []certMetric{
		{cn: "web.example.com", issuer: "Let's Encrypt", durationUntilExpiry: 100},
		{cn: "internal.corp.local", issuer: "Internal CA", durationUntilExpiry: 200},
		{cn: "api.example.com", issuer: "DigiCert", durationUntilExpiry: 300},
		{cn: "db.internal", issuer: "Internal CA", durationUntilExpiry: 400},
		{cn: "spiffe://cluster.local/ns/foo", issuer: "spiffe://cluster.local/ca", durationUntilExpiry: 500},
	}

	tests := []struct {
		name               string
		excludeCNGlobs     []string
		excludeIssuerGlobs []string
		wantCNs            []string
	}{
		{
			name:    "no exclude globs - all pass through",
			wantCNs: []string{"web.example.com", "internal.corp.local", "api.example.com", "db.internal", "spiffe://cluster.local/ns/foo"},
		},
		{
			name:           "exclude by CN glob",
			excludeCNGlobs: []string{"*.example.com"},
			wantCNs:        []string{"internal.corp.local", "db.internal", "spiffe://cluster.local/ns/foo"},
		},
		{
			name:               "exclude by issuer glob",
			excludeIssuerGlobs: []string{"Internal CA"},
			wantCNs:            []string{"web.example.com", "api.example.com", "spiffe://cluster.local/ns/foo"},
		},
		{
			name:               "exclude by multiple criteria",
			excludeCNGlobs:     []string{"web.*"},
			excludeIssuerGlobs: []string{"DigiCert"},
			wantCNs:            []string{"internal.corp.local", "db.internal", "spiffe://cluster.local/ns/foo"},
		},
		{
			name:           "exclude a URI CN with a wildcard that has to cross slashes",
			excludeCNGlobs: []string{"spiffe://*"},
			wantCNs:        []string{"web.example.com", "internal.corp.local", "api.example.com", "db.internal"},
		},
		{
			name:               "exclude a URI issuer with a wildcard that has to cross slashes",
			excludeIssuerGlobs: []string{"spiffe://*"},
			wantCNs:            []string{"web.example.com", "internal.corp.local", "api.example.com", "db.internal"},
		},
		{
			name:           "exclude all with wildcard",
			excludeCNGlobs: []string{"*"},
			wantCNs:        []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterMetrics(inputMetrics, tt.excludeCNGlobs, tt.excludeIssuerGlobs)

			if len(result) != len(tt.wantCNs) {
				t.Fatalf("filterMetrics() returned %d metrics, want %d", len(result), len(tt.wantCNs))
			}
			for i, wantCN := range tt.wantCNs {
				if result[i].cn != wantCN {
					t.Errorf("filterMetrics()[%d].cn = %q, want %q", i, result[i].cn, wantCN)
				}
			}
		})
	}
}
