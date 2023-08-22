// Licensed under the Apache-2.0 license

package verification

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"testing"

	zx509 "github.com/zmap/zcrypto/x509"
	zlint "github.com/zmap/zlint/v3"
	"github.com/zmap/zlint/v3/lint"
	"golang.org/x/exp/slices"
)

// This file is used to test the certify key command by using a simulator/emulator

func GetTestTarget_CertifyKey(support_needed []string) ([]TestDPEInstance, error) {

	var instances []TestDPEInstance
	var err error
	if testTargetType == EMULATOR {
		for i := 0; i < len(support_needed); i++ {
			if !slices.Contains(emulator_supports, support_needed[i]) {
				return nil, errors.New("Requested support is not supported in emulator")
			}
		}
		instances, err = GetEmulatorTarget(support_needed, instances)
		if err != nil {
			return nil, err
		}
		return instances, nil
	} else if testTargetType == SIMULATOR {
		instances = []TestDPEInstance{
			// No extra options besides AutoInit.
			&DpeSimulator{exe_path: *socket_exe, supports: Support{AutoInit: true, X509: true}},
			// Supports AutoInit and simulation contexts.
			&DpeSimulator{exe_path: *socket_exe, supports: Support{AutoInit: true, Simulation: true, X509: true}},
		}
		for _, instance := range instances {
			instance.SetLocality(DPE_SIMULATOR_AUTO_INIT_LOCALITY)
		}
		return instances, nil
	}

	return nil, errors.New("Error in creating dpe instances - supported feature is not enabled")
}

func TestCertifyKey(t *testing.T) {

	// Added dummy support for emulator
	support_needed := []string{"AutoInit", "X509"}

	instances, err := GetTestTarget_CertifyKey(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in emulator" {
			log.Print("Warning: Failed executing TestCertifyKey command due to unsupported request. Hence, skipping it")
			t.Skipf("Skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}

	for _, instance := range instances {
		testCertifyKey(instance, t)
	}
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
	client, err := NewClient256(d)
	if err != nil {
		t.Fatalf("Could not initialize client: %v", err)
	}

	certifyKeyReq := CertifyKeyReq[SHA256Digest]{
		ContextHandle: [16]byte{0},
		Flags:         0,
		Label:         [32]byte{0},
		Format:        CertifyKeyX509,
	}

	certifyKeyResp, err := client.CertifyKey(&certifyKeyReq)
	if err != nil {
		t.Fatalf("Could not certify key: %v", err)
	}
	checkCertificateStructure(t, certifyKeyResp.Certificate)

	// TODO: When DeriveChild is implemented, call it here to add more TCIs and call CertifyKey again.
}
