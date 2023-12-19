// Licensed under the Apache-2.0 license

package verification

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"

	zx509 "github.com/zmap/zcrypto/x509"
	zlint "github.com/zmap/zlint/v3"
	"github.com/zmap/zlint/v3/lint"
)

func TestGetCertificateChain(d TestDPEInstance, client DPEClient, t *testing.T) {
	certChain, err := client.GetCertificateChain()
	if err != nil {
		t.Fatalf("[FATAL]: Could not get Certificate Chain: %v", err)
	}

	checkCertificateChain(t, certChain)
}

func checkCertificateChain(t *testing.T, certData []byte) []*x509.Certificate {
	t.Helper()
	failed := false

	var x509Certs []*x509.Certificate
	var err error

	// Check whether certificate chain is DER encoded.
	if x509Certs, err = x509.ParseCertificates(certData); err != nil {
		t.Fatalf("[FATAL]: Could not parse certificate using crypto/x509: %v", err)
	}

	// Parse the cert with zcrypto so we can lint it.
	certs, err := zx509.ParseCertificates(certData)
	if err != nil {
		t.Errorf("[ERROR]: Could not parse certificate using zcrypto/x509: %v", err)
		failed = true
	}

	// zlint provides a lot of linter sources. Limit results to just the relevant RFCs.
	// For a full listing of supported linter sources, see https://github.com/zmap/zlint/blob/master/v3/lint/source.go
	registry, err := lint.GlobalRegistry().Filter(lint.FilterOptions{
		IncludeSources: lint.SourceList{
			lint.RFC3279,
			lint.RFC5280,
			lint.RFC5480,
			lint.RFC5891,
			lint.RFC8813,
		},
		ExcludeNames: []string{
			// It is fine for cert chains to always use GeneralizedTime, UTCTime is
			// strictly worse and mixing the two formats does not lend itself well
			// to fixed-sized X.509 templating.
			"e_wrong_time_format_pre2050",
		},
	})
	if err != nil {
		t.Fatalf("[FATAL]: Could not set up zlint registry: %v", err)
	}

	for _, cert := range certs {
		results := zlint.LintCertificateEx(cert, registry)

		for id, result := range results.Results {
			var level string
			switch result.Status {
			case lint.Error:
				level = "ERROR"
			case lint.Warn:
				level = "WARN"
			default:
				continue
			}
			details := result.Details
			if details != "" {
				details = fmt.Sprintf("%s. ", details)
			}
			l := registry.ByName(id)

			t.Errorf("[LINT %s] %s: %s%s (%s)", level, l.Source, details, l.Description, l.Citation)
			failed = true
		}

		if failed {
			// Dump the cert in PEM for use with various tools
			t.Logf("[LINT]: Offending certificate: %s\n", cert.Subject.String())
			t.Logf("[LINT]: Offending certificate (PEM):\n%s", (string)(pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			})))
		}
	}

	validateCertChain(t, x509Certs)
	return x509Certs
}

// Build certificate chain and calls to validateSignature on each chain.
func validateCertChain(t *testing.T, certChain []*x509.Certificate) {
	t.Helper()

	certsToProcess := certChain

	// Remove unhandled critical extensions reported by x509 but defined in spec
	removeTcgDiceCriticalExtensions(t, certsToProcess)

	// Remove unhandled extended key usages reported by x509 but defined in spec
	removeTcgDiceExtendedKeyUsages(t, certsToProcess)

	// Build verify options
	opts := buildVerifyOptions(t, certChain)

	// Certificate chain validation for each intermediate certificate
	for _, cert := range certChain {
		chains, err := cert.Verify(opts)
		if err != nil {
			t.Errorf("[ERROR]: Error in Certificate Chain of %s: %s", cert.Subject, err.Error())
		}

		// Log certificate chains linked to each cetificate in chain
		if len(chains) != 1 {
			t.Errorf("[ERROR]: validateCertChain certificate chain is empty")
		}
	}
}
