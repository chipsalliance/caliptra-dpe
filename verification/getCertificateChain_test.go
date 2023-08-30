// Licensed under the Apache-2.0 license

package verification

import (
	"crypto/x509"
	"encoding/pem"
	"log"
	"strings"
	"testing"
)

// This file is used to test the Get Certificate Chain command by using a simulator/emulator

func TestGetCertificateChain(t *testing.T) {
	support_needed := []string{"AutoInit", "X509"}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in the emulator" {
			t.Skipf("Warning: Failed executing TestGetCertificateChain command due to unsupported request. Hence, skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}
	testGetCertificateChain(instance, t)
}

func TestGetCertificateChain_SimulationMode(t *testing.T) {

	support_needed := []string{"AutoInit", "Simulation", "X509"}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in the emulator" {
			t.Skipf("Warning: Failed executing TestGetCertificateChain_SimulationMode command due to unsupported request. Hence, skipping the command execution")
		} else {
			log.Fatal(err)
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
		t.Fatalf("Could not initialize client: %v", err)
	}

	// Initialize request input parameters
	getCertificateChainReq := GetCertificateChainReq{
		Offset: 0,
		Size:   MAX_CERT_CHUNK_SIZE,
	}

	getCertificateChainResp, err := client.GetCertificateChain(&getCertificateChainReq)
	if err != nil {
		t.Fatalf("Could not get Certificate Chain: %v", err)
	}

	//fmt.Println(getCertificateChainResp)
	checkCertificateChain(t, getCertificateChainResp.CertificateChain)

	// TODO: When DeriveChild is implemented, call it here to add more TCIs and call GetCertificateChain again.
}

func checkCertificateChain(t *testing.T, certData []byte) {
	t.Helper()
	failed := false

	// QUERY
	// The certiifcate chain data is returned as Base64 encoded PEM string instead of DER.
	// This is understandable as opposed to CertifyKey command, a chain of certs will be returned.
	// So, the x509 parsing employed for CertifyKey will not work.
	// We had to prefix and suffix the "BEGIN CERTIFICATE", "END CERTIFICATE"
	// This is possible currently as the GetCertificateChain command returns just single certificate.
	// This will become a trouble if multiple certs are returned as there would
	//    not be a way to demarcate one cert from another in certificate chain

	certstr := "-----BEGIN CERTIFICATE-----\n" + strings.ReplaceAll(string(certData), "\x00", "") + "\n-----END CERTIFICATE-----"
	certData = []byte(certstr)
	block, _ := pem.Decode(certData)
	//fmt.Println(block.Bytes)
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatalf("Could not parse certificate using crypto/x509: %v", err)
		failed = true
	}

	// TODO: Need to add these validations on PEM cert received.
	// zcrypto desnt work with PEM block,
	// such as converting each cert into DER format and then validating te same.

	// // Parse the cert with zcrypto so we can lint it.
	// cert, err := zx509.ParseCertificate(certData)
	// if err != nil {
	// 	t.Errorf("Could not parse certificate using zcrypto/x509: %v", err)
	// 	failed = true
	// }

	// // zlint provides a lot of linter sources. Limit results to just the relevant RFCs.
	// // For a full listing of supported linter sources, see https://github.com/zmap/zlint/blob/master/v3/lint/source.go
	// registry, err := lint.GlobalRegistry().Filter(lint.FilterOptions{
	// 	IncludeSources: lint.SourceList{
	// 		lint.RFC3279,
	// 		lint.RFC5280,
	// 		lint.RFC5480,
	// 		lint.RFC5891,
	// 		lint.RFC8813,
	// 	}})
	// if err != nil {
	// 	t.Fatalf("Could not set up zlint registry: %v", err)
	// }

	// results := zlint.LintCertificateEx(cert, registry)

	// for id, result := range results.Results {
	// 	var level string
	// 	switch result.Status {
	// 	case lint.Error:
	// 		level = "ERROR"
	// 	case lint.Warn:
	// 		level = "WARN"
	// 	default:
	// 		continue
	// 	}
	// 	details := result.Details
	// 	if details != "" {
	// 		details = fmt.Sprintf("%s. ", details)
	// 	}
	// 	l := registry.ByName(id)
	// 	// TODO(https://github.com/chipsalliance/caliptra-dpe/issues/74):
	// 	// Fail the test with Errorf here once we expect it to pass.
	// 	t.Logf("[%s] %s: %s%s (%s)", level, l.Source, details, l.Description, l.Citation)
	// 	failed = true
	// }

	// TODO: Need to modify according to cert data format
	if failed {
		// Dump the cert in PEM and hex for use with various tools
		t.Logf("Offending certificate (PEM):\n%s", (string)(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certData,
		})))
		t.Logf("Offending certificate (DER):\n%x", certData)
	}
}
