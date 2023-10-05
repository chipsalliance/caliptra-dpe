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

// This file is used to test the certify key command by using a simulator/emulator

func TestCertifyKey(t *testing.T) {

	support_needed := []string{"AutoInit", "X509"}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in the emulator" {
			t.Skipf("Warning: Failed executing TestCertifyKey command due to unsupported request. Hence, skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}
	testCertifyKey(instance, t)
}

func TestCertifyKey_SimulationMode(t *testing.T) {

	support_needed := []string{"AutoInit", "Simulation", "X509"}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in the emulator" {
			t.Skipf("Warning: Failed executing TestCertifyKey_SimulationMode command due to unsupported request. Hence, skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}
	testCertifyKey(instance, t)
}

func checkCertificateStructure(t *testing.T, certData []byte) {
	t.Helper()
	failed := false

	// Most likely redundant with zx509 check below, but check that the regular x509 library can parse the cert.
	if _, err := x509.ParseCertificate(certData); err != nil {
		t.Fatalf("Could not parse certificate using crypto/x509: %v", err)
		failed = true
	}

	// Parse the cert with zcrypto so we can lint it.
	cert, err := zx509.ParseCertificate(certData)
	if err != nil {
		t.Errorf("Could not parse certificate using zcrypto/x509: %v", err)
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
		t.Fatalf("Could not set up zlint registry: %v", err)
	}

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
		t.Logf("Offending certificate (PEM):\n%s", (string)(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certData,
		})))
		t.Logf("Offending certificate (DER):\n%x", certData)
	}
}

func testCertifyKey(d TestDPEInstance, t *testing.T) {
	if d.HasPowerControl() {
		err := d.PowerOn()
		if err != nil {
			log.Fatal(err)
		}
		defer d.PowerOff()
	}
	var client256 *Client256
	var client384 *Client384
	var err error

	if d.GetProfile() == DPE_EMULATOR_PROFILE {
		client384, err = NewClient384(d)
	} else {
		client256, err = NewClient256(d)
	}
	if err != nil {
		t.Fatalf("Could not initialize client: %v", err)
	}

	if d.GetProfile() == DPE_EMULATOR_PROFILE {
		certifyKeyReq := CertifyKeyReq[SHA384Digest]{
			ContextHandle: [16]byte{0},
			Flags:         0,
			Label:         [48]byte{0},
			Format:        CertifyKeyX509,
		}

		certifyKeyResp, err := client384.CertifyKey(&certifyKeyReq)
		if err != nil {
			t.Fatalf("Could not certify key: %v", err)
		}
		checkCertificateStructure(t, certifyKeyResp.Certificate)
	} else {
		certifyKeyReq := CertifyKeyReq[SHA256Digest]{
			ContextHandle: [16]byte{0},
			Flags:         0,
			Label:         [32]byte{0},
			Format:        CertifyKeyX509,
		}

		certifyKeyResp, err := client256.CertifyKey(&certifyKeyReq)
		if err != nil {
			t.Fatalf("Could not certify key: %v", err)
		}
		checkCertificateStructure(t, certifyKeyResp.Certificate)
	}

	// TODO: When DeriveChild is implemented, call it here to add more TCIs and call CertifyKey again.
}
