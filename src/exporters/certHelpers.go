package exporters

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/pavlo-v-chernykh/keystore-go/v4"
	"software.sslmate.com/src/go-pkcs12"
)

type certMetric struct {
	durationUntilExpiry float64
	notAfter, notBefore float64
	issuer              string
	cn                  string
	// serial is the certificate serial number in lowercase hex. Used as a
	// Prometheus label so multiple PEMs that share cn/issuer (e.g. rotated
	// service-CA bundles) do not overwrite one another.
	serial string
}

func secondsToExpiryFromCertAsFile(file, certPassword string) ([]certMetric, error) {
	certBytes, err := os.ReadFile(file)
	if err != nil {
		return []certMetric{}, err
	}

	return secondsToExpiryFromCertAsBytes(certBytes, certPassword)
}

func secondsToExpiryFromCertAsBase64String(s string) ([]certMetric, error) {
	certBytes, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return []certMetric{}, err
	}

	return secondsToExpiryFromCertAsBytes(certBytes, "")
}

func secondsToExpiryFromCertAsBytes(certBytes []byte, certPassword string) ([]certMetric, error) {
	var metrics []certMetric

	parsed, metrics, pemErr := parseAsPEM(certBytes)
	if parsed {
		return metrics, pemErr
	}
	// Fall back to PKCS#12 for binary keystore formats (.p12/.pfx).
	parsed, metrics, pkcsErr := parseAsPKCS(certBytes, certPassword)
	if parsed {
		return metrics, nil
	}
	// JKS keystores are identified by their own magic number, so a failure
	// there is reported in preference to the PEM and PKCS#12 guesses.
	parsed, metrics, jksErr := parseAsJKS(certBytes, certPassword)
	if parsed {
		return metrics, jksErr
	}
	// A JCEKS store is a different format entirely, and naming it saves the
	// operator from chasing a PEM parse failure.
	if looksLikeJCEKS(certBytes) {
		return nil, fmt.Errorf("jceks keystores are not supported, convert the store to jks or pkcs12")
	}
	// Prefer the PEM error when the payload is clearly textual; PKCS#12 ASN.1
	// errors on garbage text are noisy and change across crypto/asn1 versions.
	if pemErr != nil && !looksLikePKCS12(certBytes) {
		return nil, fmt.Errorf("failed to parse as pem, pkcs12 or jks: %w", pemErr)
	}
	if pkcsErr != nil {
		return nil, fmt.Errorf("failed to parse as pem, pkcs12 or jks: %w", pkcsErr)
	}
	return nil, fmt.Errorf("failed to parse as pem, pkcs12 or jks")
}

// looksLikePKCS12 reports whether data might be a PKCS#12/PFX binary.
// PKCS#12 is an ASN.1 SEQUENCE (tag 0x30); PEM text never starts that way.
func looksLikePKCS12(data []byte) bool {
	return len(data) > 0 && data[0] == 0x30
}

var (
	jksMagic   = []byte{0xfe, 0xed, 0xfe, 0xed}
	jceksMagic = []byte{0xce, 0xce, 0xce, 0xce}
)

// looksLikeJKS reports whether data starts with the JKS magic number.
func looksLikeJKS(data []byte) bool {
	return bytes.HasPrefix(data, jksMagic)
}

// looksLikeJCEKS reports whether data starts with the JCEKS magic number.
// JCEKS is a different format that this exporter cannot read, but saying so is
// more useful than reporting a PEM parse failure.
func looksLikeJCEKS(data []byte) bool {
	return bytes.HasPrefix(data, jceksMagic)
}

func getCertificateMetrics(cert *x509.Certificate) certMetric {
	var metric certMetric
	metric.notAfter = float64(cert.NotAfter.Unix())
	metric.notBefore = float64(cert.NotBefore.Unix())
	metric.durationUntilExpiry = time.Until(cert.NotAfter).Seconds()
	metric.issuer = cert.Issuer.CommonName
	metric.cn = cert.Subject.CommonName
	if cert.SerialNumber != nil {
		metric.serial = cert.SerialNumber.Text(16)
	}
	return metric
}

func parseAsPKCS(certBytes []byte, certPassword string) (bool, []certMetric, error) {
	var metrics []certMetric
	_, cert, caCerts, err := pkcs12.DecodeChain(certBytes, certPassword)
	if err != nil {
		return false, nil, err
	}
	metric := getCertificateMetrics(cert)
	metrics = append(metrics, metric)
	for _, cert := range caCerts {
		metric := getCertificateMetrics(cert)
		metrics = append(metrics, metric)
	}
	return true, metrics, nil
}

const (
	// jksMinEntrySize is the smallest byte length a JKS entry can occupy: a
	// 4-byte tag, a 2-byte alias length, an 8-byte creation date and a 4-byte
	// length for the payload that follows.
	jksMinEntrySize = 18
	// jksDigestSize is the length of the digest JKS stores after the entries.
	jksDigestSize = 20
)

// jksCursor reads big-endian fields with a bounds check on every access.
type jksCursor struct {
	data []byte
	pos  int
}

func (c *jksCursor) u16() (uint16, error) {
	if c.pos+2 > len(c.data) {
		return 0, fmt.Errorf("truncated at byte %d", c.pos)
	}
	v := binary.BigEndian.Uint16(c.data[c.pos:])
	c.pos += 2
	return v, nil
}

func (c *jksCursor) u32() (uint32, error) {
	if c.pos+4 > len(c.data) {
		return 0, fmt.Errorf("truncated at byte %d", c.pos)
	}
	v := binary.BigEndian.Uint32(c.data[c.pos:])
	c.pos += 4
	return v, nil
}

func (c *jksCursor) skip(n uint32) error {
	if uint64(c.pos)+uint64(n) > uint64(len(c.data)) {
		return fmt.Errorf("declared length %d at byte %d exceeds the %d bytes that remain", n, c.pos, len(c.data)-c.pos)
	}
	c.pos += int(n)
	return nil
}

func (c *jksCursor) skipPrefixed16() error {
	n, err := c.u16()
	if err != nil {
		return err
	}
	return c.skip(uint32(n))
}

func (c *jksCursor) skipPrefixed32() error {
	n, err := c.u32()
	if err != nil {
		return err
	}
	return c.skip(n)
}

// validateJKSFraming walks the keystore framing and reports the first declared
// length or count that cannot fit in the payload.
//
// This has to happen before the keystore is handed to the decoder, which sizes
// its allocations straight from those fields. An absurd length there makes Go
// fail the allocation fatally, which no recover can catch, so a truncated or
// crafted file would take the whole process down.
func validateJKSFraming(data []byte) error {
	c := jksCursor{data: data}
	if _, err := c.u32(); err != nil { // magic, already matched by the caller
		return err
	}
	version, err := c.u32()
	if err != nil {
		return err
	}
	if version != 1 && version != 2 {
		return fmt.Errorf("unsupported keystore version %d", version)
	}
	entries, err := c.u32()
	if err != nil {
		return err
	}
	if uint64(entries)*jksMinEntrySize > uint64(len(data)) {
		return fmt.Errorf("declares %d entries, more than %d bytes can hold", entries, len(data))
	}

	for i := uint32(0); i < entries; i++ {
		tag, err := c.u32()
		if err != nil {
			return err
		}
		if err := c.skipPrefixed16(); err != nil { // alias
			return err
		}
		if err := c.skip(8); err != nil { // creation date
			return err
		}

		switch tag {
		case 1: // private key entry
			if err := c.skipPrefixed32(); err != nil { // encrypted key
				return err
			}
			chain, err := c.u32()
			if err != nil {
				return err
			}
			if uint64(chain)*4 > uint64(len(data)) {
				return fmt.Errorf("entry %d declares a %d-certificate chain, more than %d bytes can hold", i, chain, len(data))
			}
			for j := uint32(0); j < chain; j++ {
				if version == 2 {
					if err := c.skipPrefixed16(); err != nil { // certificate type
						return err
					}
				}
				if err := c.skipPrefixed32(); err != nil { // certificate
					return err
				}
			}
		case 2: // trusted certificate entry
			if version == 2 {
				if err := c.skipPrefixed16(); err != nil { // certificate type
					return err
				}
			}
			if err := c.skipPrefixed32(); err != nil { // certificate
				return err
			}
		default:
			return fmt.Errorf("entry %d has unknown tag %d", i, tag)
		}
	}

	if remaining := len(data) - c.pos; remaining != jksDigestSize {
		return fmt.Errorf("expected a %d-byte digest after the last entry, found %d bytes", jksDigestSize, remaining)
	}
	return nil
}

// parseAsJKS reads certificates out of a Java KeyStore, covering trusted
// certificate entries and the chains attached to private key entries.
//
// Only certificates are read. A JKS stores the chain of a private key entry in
// the clear, so no key password is involved and the private key is never
// decrypted.
//
// A keystore can hold several entries sharing a cn and issuer, which collapse
// into one Prometheus series unless --include-serial-label is set.
func parseAsJKS(certBytes []byte, certPassword string) (bool, []certMetric, error) {
	if !looksLikeJKS(certBytes) {
		return false, nil, nil
	}
	if err := validateJKSFraming(certBytes); err != nil {
		return true, nil, fmt.Errorf("malformed jks keystore: %w", err)
	}

	// Ordered aliases keep the exported series stable from one poll to the
	// next; case-exact aliases stop an entry whose alias carries uppercase
	// characters from being invisible to the lookups below.
	ks := keystore.New(keystore.WithOrderedAliases(), keystore.WithCaseExactAliases())
	if err := ks.Load(bytes.NewReader(certBytes), []byte(certPassword)); err != nil {
		// The magic number says JKS, so this is a real failure (typically a
		// wrong or missing password), not a format mismatch.
		return true, nil, fmt.Errorf("failed to load jks keystore: %w", err)
	}

	var metrics []certMetric
	for _, alias := range ks.Aliases() {
		var chain []keystore.Certificate

		switch {
		case ks.IsTrustedCertificateEntry(alias):
			entry, err := ks.GetTrustedCertificateEntry(alias)
			if err != nil {
				return true, metrics, fmt.Errorf("failed to read trusted certificate entry %q: %w", alias, err)
			}
			chain = []keystore.Certificate{entry.Certificate}
		case ks.IsPrivateKeyEntry(alias):
			var err error
			chain, err = ks.GetPrivateKeyEntryCertificateChain(alias)
			if err != nil {
				return true, metrics, fmt.Errorf("failed to read the certificate chain of %q: %w", alias, err)
			}
		default:
			return true, metrics, fmt.Errorf("entry %q is neither a trusted certificate nor a private key entry", alias)
		}

		for i, entryCert := range chain {
			cert, err := x509.ParseCertificate(entryCert.Content)
			if err != nil {
				return true, metrics, fmt.Errorf("failed to parse certificate %d of %q: %w", i, alias, err)
			}
			metrics = append(metrics, getCertificateMetrics(cert))
		}
	}

	return true, metrics, nil
}

func parseAsPEM(certBytes []byte) (bool, []certMetric, error) {
	var metrics []certMetric
	var blocks []*pem.Block

	block, rest := pem.Decode(certBytes)
	if block == nil {
		return false, metrics, fmt.Errorf("Failed to parse as a pem")
	}
	// Remove trailing whitespaces to prevent possible error in loop
	rest = []byte(strings.TrimRightFunc(string(rest), unicode.IsSpace))
	if block.Type == "CERTIFICATE" {
		blocks = append(blocks, block)
	}
	// Export the remaining certificates in the certificate chain
	for len(rest) != 0 {
		block, rest = pem.Decode(rest)
		if block == nil {
			return true, metrics, fmt.Errorf("Failed to parse intermediate as a pem")
		}
		if block.Type == "CERTIFICATE" {
			blocks = append(blocks, block)
		}
	}
	for _, block := range blocks {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return true, metrics, err
		}
		metric := getCertificateMetrics(cert)
		metrics = append(metrics, metric)
	}
	return true, metrics, nil
}
