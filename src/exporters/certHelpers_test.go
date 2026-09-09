package exporters

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/joe-elliott/cert-exporter/internal/testutil"
	"github.com/pavlo-v-chernykh/keystore-go/v4"
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

// jksWithTrustedCerts builds an in-memory JKS holding one trusted certificate
// entry per supplied bundle, keyed by the given aliases.
func jksWithTrustedCerts(t *testing.T, password string, certs map[string]*testutil.CertBundle) []byte {
	t.Helper()

	ks := keystore.New()
	for alias, bundle := range certs {
		entry := keystore.TrustedCertificateEntry{
			CreationTime: time.Now(),
			Certificate: keystore.Certificate{
				Type:    "X.509",
				Content: bundle.Cert.Raw,
			},
		}
		if err := ks.SetTrustedCertificateEntry(alias, entry); err != nil {
			t.Fatalf("SetTrustedCertificateEntry(%q) failed: %v", alias, err)
		}
	}

	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(password)); err != nil {
		t.Fatalf("Store() failed: %v", err)
	}
	return buf.Bytes()
}

// jksWithPrivateKey builds an in-memory JKS holding a private key entry whose
// chain is the supplied certificates, leaf first. keyPassword protects the key.
func jksWithPrivateKey(t *testing.T, storePassword, keyPassword string, alias string, chain ...*testutil.CertBundle) []byte {
	t.Helper()

	key, err := x509.MarshalPKCS8PrivateKey(chain[0].PrivateKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() failed: %v", err)
	}

	certs := make([]keystore.Certificate, 0, len(chain))
	for _, bundle := range chain {
		certs = append(certs, keystore.Certificate{Type: "X.509", Content: bundle.Cert.Raw})
	}

	ks := keystore.New()
	entry := keystore.PrivateKeyEntry{
		CreationTime:     time.Now(),
		PrivateKey:       key,
		CertificateChain: certs,
	}
	if err := ks.SetPrivateKeyEntry(alias, entry, []byte(keyPassword)); err != nil {
		t.Fatalf("SetPrivateKeyEntry() failed: %v", err)
	}

	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(storePassword)); err != nil {
		t.Fatalf("Store() failed: %v", err)
	}
	return buf.Bytes()
}

func TestParseAsJKSTrustedCertificates(t *testing.T) {
	const password = "changeit"
	first := testutil.GenerateCertificate(t, testutil.CertConfig{CommonName: "first-ca", Days: 90, IsCA: true})
	second := testutil.GenerateCertificate(t, testutil.CertConfig{CommonName: "second-ca", Days: 90, IsCA: true})

	store := jksWithTrustedCerts(t, password, map[string]*testutil.CertBundle{
		"first":  first,
		"second": second,
	})

	parsed, metrics, err := parseAsJKS(store, password)
	if !parsed {
		t.Fatal("parseAsJKS() reported the payload is not a keystore")
	}
	if err != nil {
		t.Fatalf("parseAsJKS() returned %v, want nil", err)
	}
	if len(metrics) != 2 {
		t.Fatalf("parseAsJKS() returned %d metrics, want 2", len(metrics))
	}

	found := map[string]bool{}
	for _, m := range metrics {
		found[m.cn] = true
	}
	for _, cn := range []string{"first-ca", "second-ca"} {
		if !found[cn] {
			t.Errorf("missing a metric for cn %q, got %v", cn, found)
		}
	}
}

func TestParseAsJKSPrivateKeyChain(t *testing.T) {
	const password = "changeit"
	bundle := testutil.GenerateCertificate(t, testutil.CertConfig{CommonName: "keyed-cert", Days: 90})
	store := jksWithPrivateKey(t, password, password, "keyed", bundle)

	parsed, metrics, err := parseAsJKS(store, password)
	if !parsed || err != nil {
		t.Fatalf("parseAsJKS() = (%v, _, %v), want (true, _, nil)", parsed, err)
	}
	if len(metrics) != 1 {
		t.Fatalf("parseAsJKS() returned %d metrics, want 1", len(metrics))
	}
	if metrics[0].cn != "keyed-cert" {
		t.Errorf("cn = %q, want %q", metrics[0].cn, "keyed-cert")
	}
}

// A JKS stores the certificate chain of a private key entry in the clear, so a
// key protected by its own password must not stop the chain being exported.
func TestParseAsJKSKeyWithOwnPasswordStillExportsChain(t *testing.T) {
	const storePassword = "changeit"
	bundle := testutil.GenerateCertificate(t, testutil.CertConfig{CommonName: "keyed-cert", Days: 90})
	store := jksWithPrivateKey(t, storePassword, "a-different-password", "keyed", bundle)

	parsed, metrics, err := parseAsJKS(store, storePassword)
	if !parsed {
		t.Fatal("parseAsJKS() reported the payload is not a keystore")
	}
	if err != nil {
		t.Fatalf("parseAsJKS() returned %v, want nil", err)
	}
	if len(metrics) != 1 || metrics[0].cn != "keyed-cert" {
		t.Fatalf("got %v, want a single metric for keyed-cert", metrics)
	}
}

// A server keystore holds a leaf plus its issuers, and every certificate in
// that chain has its own expiry worth exporting.
func TestParseAsJKSExportsWholeChain(t *testing.T) {
	const password = "changeit"
	ca := testutil.GenerateCertificate(t, testutil.CertConfig{CommonName: "chain-ca", Days: 365, IsCA: true})
	leaf := testutil.GenerateSignedCertificate(t, testutil.CertConfig{CommonName: "chain-leaf", Days: 90}, ca)
	store := jksWithPrivateKey(t, password, password, "chained", leaf, ca)

	parsed, metrics, err := parseAsJKS(store, password)
	if !parsed || err != nil {
		t.Fatalf("parseAsJKS() = (%v, _, %v), want (true, _, nil)", parsed, err)
	}
	if len(metrics) != 2 {
		t.Fatalf("parseAsJKS() returned %d metrics, want 2 (leaf and issuer)", len(metrics))
	}
	got := []string{metrics[0].cn, metrics[1].cn}
	want := []string{"chain-leaf", "chain-ca"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("metrics[%d].cn = %q, want %q (chain order should be preserved)", i, got[i], want[i])
		}
	}
}

func TestParseAsJKSWrongPassword(t *testing.T) {
	bundle := testutil.GenerateCertificate(t, testutil.CertConfig{CommonName: "first-ca", Days: 90, IsCA: true})
	store := jksWithTrustedCerts(t, "changeit", map[string]*testutil.CertBundle{"first": bundle})

	parsed, _, err := parseAsJKS(store, "wrong")
	if !parsed {
		t.Error("parseAsJKS() reported a format mismatch, want it recognised by magic number")
	}
	if err == nil {
		t.Error("parseAsJKS() returned nil, want an error for the wrong password")
	}
}

func TestParseAsJKSRejectsOtherFormats(t *testing.T) {
	bundle := testutil.GenerateCertificate(t, testutil.CertConfig{CommonName: "pem-cert", Days: 90})

	for name, payload := range map[string][]byte{
		"pem":   bundle.CertPEM,
		"empty": {},
		"short": {0xfe, 0xed},
		"junk":  []byte("not a keystore"),
	} {
		t.Run(name, func(t *testing.T) {
			parsed, metrics, err := parseAsJKS(payload, "")
			if parsed {
				t.Error("parseAsJKS() claimed the payload is a keystore")
			}
			if err != nil {
				t.Errorf("parseAsJKS() returned %v, want nil for a format mismatch", err)
			}
			if metrics != nil {
				t.Errorf("parseAsJKS() returned %v, want no metrics", metrics)
			}
		})
	}
}

// The password has to reach the parser from the exporter, which is what the
// --cert-password-file flag feeds.
func TestSecondsToExpiryFromCertAsFileReadsJKS(t *testing.T) {
	const password = "changeit"
	bundle := testutil.GenerateCertificate(t, testutil.CertConfig{CommonName: "store-cert", Days: 90, IsCA: true})
	store := jksWithTrustedCerts(t, password, map[string]*testutil.CertBundle{"store": bundle})

	file := filepath.Join(t.TempDir(), "keystore.jks")
	if err := os.WriteFile(file, store, 0o600); err != nil {
		t.Fatalf("WriteFile() failed: %v", err)
	}

	metrics, err := secondsToExpiryFromCertAsFile(file, password)
	if err != nil {
		t.Fatalf("secondsToExpiryFromCertAsFile() returned %v, want nil", err)
	}
	if len(metrics) != 1 || metrics[0].cn != "store-cert" {
		t.Fatalf("got %v, want a single metric for store-cert", metrics)
	}

	if _, err := secondsToExpiryFromCertAsFile(file, ""); err == nil {
		t.Error("secondsToExpiryFromCertAsFile() with no password returned nil, want an error")
	}
}

// The keystore decoder sizes allocations straight from the framing fields, and
// an absurd length there fails the allocation fatally rather than returning an
// error, so the framing is checked before the payload is handed over.
func TestParseAsJKSRejectsImpossibleFraming(t *testing.T) {
	// magic, version 2, one entry, tag 1 (private key), alias "a",
	// creation date, a 4-byte key, then a chain count of 0xFFFFFFFF.
	hostileChainCount := []byte{
		0xfe, 0xed, 0xfe, 0xed,
		0x00, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x01, 'a',
		0x00, 0x00, 0x01, 0xa0, 0x81, 0x6b, 0x52, 0x3c,
		0x00, 0x00, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04,
		0xff, 0xff, 0xff, 0xff,
	}
	// The same shape, but the impossible number is a certificate length.
	hostileCertLen := []byte{
		0xfe, 0xed, 0xfe, 0xed,
		0x00, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x02,
		0x00, 0x01, 'a',
		0x00, 0x00, 0x01, 0xa0, 0x81, 0x6b, 0x52, 0x3c,
		0x00, 0x05, 'X', '.', '5', '0', '9',
		0xf0, 0x00, 0x00, 0x00,
	}
	// An entry count no payload of this size could carry.
	hostileEntryCount := []byte{
		0xfe, 0xed, 0xfe, 0xed,
		0x00, 0x00, 0x00, 0x02,
		0x7f, 0xff, 0xff, 0xff,
	}
	// A tag the format does not define.
	unknownTag := []byte{
		0xfe, 0xed, 0xfe, 0xed,
		0x00, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x09,
		0x00, 0x01, 'a',
		0x00, 0x00, 0x01, 0xa0, 0x81, 0x6b, 0x52, 0x3c,
	}

	for name, payload := range map[string][]byte{
		"chain count": hostileChainCount,
		"cert length": hostileCertLen,
		"entry count": hostileEntryCount,
		"unknown tag": unknownTag,
		"header only": {0xfe, 0xed, 0xfe, 0xed},
		"bad version": {0xfe, 0xed, 0xfe, 0xed, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00},
	} {
		t.Run(name, func(t *testing.T) {
			parsed, metrics, err := parseAsJKS(payload, "changeit")
			if !parsed {
				t.Error("parseAsJKS() reported a format mismatch, want the magic number recognised")
			}
			if err == nil {
				t.Error("parseAsJKS() returned nil, want an error for impossible framing")
			}
			if metrics != nil {
				t.Errorf("parseAsJKS() returned %v, want no metrics", metrics)
			}
		})
	}
}

// A well-formed keystore must survive the framing check, including the
// trailing digest accounting.
func TestValidateJKSFramingAcceptsRealKeystores(t *testing.T) {
	const password = "changeit"
	ca := testutil.GenerateCertificate(t, testutil.CertConfig{CommonName: "framing-ca", Days: 365, IsCA: true})
	leaf := testutil.GenerateSignedCertificate(t, testutil.CertConfig{CommonName: "framing-leaf", Days: 90}, ca)

	stores := map[string][]byte{
		"trusted entries":  jksWithTrustedCerts(t, password, map[string]*testutil.CertBundle{"one": ca, "two": leaf}),
		"private key":      jksWithPrivateKey(t, password, password, "keyed", leaf),
		"multi-cert chain": jksWithPrivateKey(t, password, password, "chained", leaf, ca),
		"empty keystore":   jksWithTrustedCerts(t, password, nil),
	}

	for name, store := range stores {
		t.Run(name, func(t *testing.T) {
			if err := validateJKSFraming(store); err != nil {
				t.Errorf("validateJKSFraming() = %v, want nil", err)
			}
		})
	}
}

func TestJCEKSReportsItsOwnFormat(t *testing.T) {
	jceks := append([]byte{0xce, 0xce, 0xce, 0xce}, make([]byte, 32)...)

	if parsed, _, _ := parseAsJKS(jceks, ""); parsed {
		t.Error("parseAsJKS() claimed a JCEKS payload is a JKS keystore")
	}

	_, err := secondsToExpiryFromCertAsBytes(jceks, "")
	if err == nil {
		t.Fatal("secondsToExpiryFromCertAsBytes() returned nil, want an error")
	}
	if !strings.Contains(err.Error(), "jceks") {
		t.Errorf("error %q does not mention jceks, so the operator cannot tell what the file is", err)
	}
}

// Aliases come back in a stable order, so that when several certificates share
// a cn and issuer the same one wins every poll instead of flipping around with
// Go's map iteration order.
func TestParseAsJKSOrdersAliases(t *testing.T) {
	const password = "changeit"
	first := testutil.GenerateCertificate(t, testutil.CertConfig{CommonName: "apple-cn", Days: 90, IsCA: true})
	second := testutil.GenerateCertificate(t, testutil.CertConfig{CommonName: "zebra-cn", Days: 90, IsCA: true})

	store := jksWithTrustedCerts(t, password, map[string]*testutil.CertBundle{
		"zebra": second,
		"apple": first,
	})

	for i := 0; i < 5; i++ {
		_, metrics, err := parseAsJKS(store, password)
		if err != nil {
			t.Fatalf("parseAsJKS() returned %v, want nil", err)
		}
		if len(metrics) != 2 {
			t.Fatalf("parseAsJKS() returned %d metrics, want 2", len(metrics))
		}
		if metrics[0].cn != "apple-cn" || metrics[1].cn != "zebra-cn" {
			t.Fatalf("got order [%s %s], want [apple-cn zebra-cn] on every parse", metrics[0].cn, metrics[1].cn)
		}
	}
}

// The keystore stores an alias verbatim but looks it up case-insensitively
// unless told otherwise, so without case-exact aliases an entry whose alias
// carries uppercase characters resolves to no entry type at all.
func TestParseAsJKSMixedCaseAlias(t *testing.T) {
	const password = "changeit"
	bundle := testutil.GenerateCertificate(t, testutil.CertConfig{CommonName: "mixed-case-cn", Days: 90, IsCA: true})

	// The store has to be written case-exactly as well, otherwise the alias is
	// lowercased on the way in and the payload cannot exercise the lookup.
	ks := keystore.New(keystore.WithCaseExactAliases())
	entry := keystore.TrustedCertificateEntry{
		CreationTime: time.Now(),
		Certificate:  keystore.Certificate{Type: "X.509", Content: bundle.Cert.Raw},
	}
	if err := ks.SetTrustedCertificateEntry("MyServerCert", entry); err != nil {
		t.Fatalf("SetTrustedCertificateEntry() failed: %v", err)
	}
	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(password)); err != nil {
		t.Fatalf("Store() failed: %v", err)
	}
	store := buf.Bytes()

	parsed, metrics, err := parseAsJKS(store, password)
	if !parsed {
		t.Fatal("parseAsJKS() reported the payload is not a keystore")
	}
	if err != nil {
		t.Fatalf("parseAsJKS() returned %v, want nil", err)
	}
	if len(metrics) != 1 || metrics[0].cn != "mixed-case-cn" {
		t.Fatalf("got %v, want a single metric for mixed-case-cn", metrics)
	}
}

// Version 1 keystores omit the per-certificate type string that version 2
// carries. keystore-go only ever writes version 2, so the framing walk's
// version branches are exercised with a hand-built payload.
func TestValidateJKSFramingAcceptsVersion1(t *testing.T) {
	trusted := func() []byte {
		var b []byte
		b = append(b, 0xfe, 0xed, 0xfe, 0xed) // magic
		b = append(b, 0x00, 0x00, 0x00, 0x01) // version 1
		b = append(b, 0x00, 0x00, 0x00, 0x01) // one entry
		b = append(b, 0x00, 0x00, 0x00, 0x02) // tag: trusted certificate
		b = append(b, 0x00, 0x03, 'c', 'a', '1')
		b = append(b, 0, 0, 0, 0, 0, 0, 0, 0) // creation date
		b = append(b, 0x00, 0x00, 0x00, 0x04) // certificate length, no type string
		b = append(b, 0xde, 0xad, 0xbe, 0xef)
		return append(b, make([]byte, jksDigestSize)...)
	}()

	privateKey := func() []byte {
		var b []byte
		b = append(b, 0xfe, 0xed, 0xfe, 0xed)
		b = append(b, 0x00, 0x00, 0x00, 0x01) // version 1
		b = append(b, 0x00, 0x00, 0x00, 0x01)
		b = append(b, 0x00, 0x00, 0x00, 0x01) // tag: private key
		b = append(b, 0x00, 0x03, 'k', 'e', 'y')
		b = append(b, 0, 0, 0, 0, 0, 0, 0, 0)
		b = append(b, 0x00, 0x00, 0x00, 0x02, 0x01, 0x02) // encrypted key
		b = append(b, 0x00, 0x00, 0x00, 0x02)             // two chain certificates
		b = append(b, 0x00, 0x00, 0x00, 0x01, 0xaa)       // no type string in version 1
		b = append(b, 0x00, 0x00, 0x00, 0x01, 0xbb)
		return append(b, make([]byte, jksDigestSize)...)
	}()

	for name, payload := range map[string][]byte{
		"trusted certificate": trusted,
		"private key chain":   privateKey,
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateJKSFraming(payload); err != nil {
				t.Errorf("validateJKSFraming() = %v, want nil for a version 1 keystore", err)
			}
		})
	}
}
