// Licensed under the Apache-2.0 license

package verification

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"testing"

	zx509 "github.com/zmap/zcrypto/x509"
	zlint "github.com/zmap/zlint/v3"
	"github.com/zmap/zlint/v3/lint"
)

// This file is used to test the Get Certificate Chain command.

func TestGetCertificateChain(t *testing.T) {
	support_needed := []string{"AutoInit", "X509"}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in the emulator" {
			t.Skipf("[WARNING]: Failed executing TestGetCertificateChain command due to unsupported request. Hence, skipping the command execution")
		} else {
			log.Fatalf("[ERROR]: %s", err.Error())
		}
	}
	testGetCertificateChain(instance, t)
}

func testGetCertificateChain(d TestDPEInstance, t *testing.T) {
	if d.HasPowerControl() {
		err := d.PowerOn()
		if err != nil {
			log.Fatal(err)
		}
		defer d.PowerOff()
	}
	client, err := NewClient256(d)
	if err != nil {
		t.Fatalf("[FATAL]: Could not initialize client: %v", err)
	}

	getCertificateChainResp, err := client.GetCertificateChain()
	if err != nil {
		t.Fatalf("[FATAL]: Could not get Certificate Chain: %v", err)
	}

	checkCertificateChain(t, getCertificateChainResp.CertificateChain)
}

func checkCertificateChain(t *testing.T, certData []byte) []*x509.Certificate {
	t.Helper()
	failed := false

	var x509Certs []*x509.Certificate
	var err error

	t.Log("[LOG]: Parse the obtained certificate chain...")
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
		}})
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
			// TODO(https://github.com/chipsalliance/caliptra-dpe/issues/74):
			// Fail the test with Errorf here once we expect it to pass.
			t.Logf("[%s] %s: %s%s (%s)", level, l.Source, details, l.Description, l.Citation)
			failed = true
		}

		if failed {
			// Dump the cert in PEM and hex for use with various tools
			t.Logf("[LOG]: Offending certificate (PEM):\n%s", (string)(pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: certData,
			})))
			t.Logf("[LOG]: Offending certificate (DER):\n%x", certData)
		}
	}

	validateCertChain(t, x509Certs)
	return x509Certs
}

// Build certificate chain and calls to validateSignature on each chain.
func validateCertChain(t *testing.T, certChain []*x509.Certificate) {
	t.Helper()

	t.Log("[LOG]: Validating intermediate certificates chains...")
	certsToProcess := certChain

	// Remove unhandled critical extensions reported by x509 but defined in spec
	t.Log("[LOG]: Checking for unhandled critical certificate extensions unknown to DPE certificates profile spec...")
	removeTcgDiceCriticalExtensions(t, certsToProcess)

	// Remove unhandled extended key usages reported by x509 but defined in spec
	t.Log("[LOG]: Checking for extended key usages unknown to DPE certificates profile spec...")
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
		t.Logf("[LOG]: Chains of intermediate certificate.")
		if len(chains) != 1 {
			t.Errorf("[ERROR]: certificate chain is empty")
		}
	}

	// This indicates that signature validation found no errors each cert
	// chain of intermediate certificates
	t.Logf("[LOG]: Intermediate certificates chain validation is done")
}
