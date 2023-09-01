// Licensed under the Apache-2.0 license

package verification

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"log"
	"testing"

	zx509 "github.com/zmap/zcrypto/x509"
	zlint "github.com/zmap/zlint/v3"
	"github.com/zmap/zlint/v3/lint"

	"golang.org/x/exp/slices"
)

// This file is used to test the certify key command by using a simulator/emulator

var UNHANDLED_CRITICAL_EXTENSIONS = [...]string{"2.23.133.5.4.5", "2.23.133.5.4.4", "2.23.133.5.4.100.7", "2.23.133.5.4.100.9"}

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

// Ignores critical extensions that are unknown to x509 package
// but atleast defined in DPE certificate profile specification.
// UnhandledCriticalExtensions may have only custom extensions mentioned in spec
// unknown_ext_map collects extensions unknown to both x59 and the spec.
// positive case expects the unknown_ext_map to be empty.
func removeUnhandledCriticalExtensions(certs []*x509.Certificate) map[string][]string {
	unknown_extn_map := map[string][]string{}
	for _, cert := range certs {
		if len(cert.UnhandledCriticalExtensions) > 0 {
			unhandled_extn := []string{}
			for _, extn := range cert.UnhandledCriticalExtensions {
				if !slices.Contains(UNHANDLED_CRITICAL_EXTENSIONS[:], extn.String()) {
					unhandled_extn = append(unhandled_extn, extn.String())
				}
			}

			if len(unhandled_extn) == 0 {
				cert.UnhandledCriticalExtensions = []asn1.ObjectIdentifier{}
			} else {
				unknown_extn_map[cert.Subject.String()] = unhandled_extn
			}
		}
	}
	// The error details in thi map will be logged for convenience
	return unknown_extn_map
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

	// Get DPE leaf certificate from CertifyKey
	certifyKeyResp, err := client.CertifyKey(&certifyKeyReq)
	if err != nil {
		t.Fatalf("Could not certify key: %v", err)
	}

	// Get root and intermediate certificates to validate certificate chain of leaf cert
	getCertificateChainResp, err := client.GetCertificateChain()
	if err != nil {
		t.Fatalf("Could not get Certificate Chain: %v", err)
	}

	leaf := certifyKeyResp.Certificate
	certchain := getCertificateChainResp.CertificateChain

	// Parse and lint certificates
	checkCertificateStructure(t, leaf)
	checkCertificateChain(t, certchain)

	validateCertChain(t, certchain, leaf)

	// TODO: When DeriveChild is implemented, call it here to add more TCIs and call CertifyKey again.
}

// Validate signature of certificates
func validateSignature(certchain []*x509.Certificate) map[string]string {
	err_map := map[string]string{}
	for _, cert := range certchain {
		err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
		if err != nil {
			msg := fmt.Sprintf("Signature validation failed for certificate %s in chain with error %s", cert.Subject.String(), err.Error())
			err_map[cert.Subject.String()] = msg
		}
	}
	return err_map
}

// Validate certificate chain
func validateCertChain(t *testing.T, certchain []byte, leaf []byte) {
	var err error

	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()

	certs, _ := x509.ParseCertificates(certchain)
	if err != nil {
		t.Fatalf("Could not parse certificate chain with error %s", err.Error())
	}

	if leaf != nil {
		leafcert, err := x509.ParseCertificate(leaf)
		if err != nil {
			t.Fatalf("Could not parse leaf certificate with error %s", err.Error())
		}

		// Remove unhandled critical extensions reported by x509 but defined in spec
		unknown_ext_map := removeUnhandledCriticalExtensions([]*x509.Certificate{leafcert})
		if len(unknown_ext_map) > 0 {
			for cert_name, ext := range unknown_ext_map {
				t.Errorf("Certificate \"%s\" has unknown UnhandledCriticalExtension \"%s\"", cert_name, ext)
			}
			t.Fatalf("Cannot proceed leaf certificate chain validation with non-empty unhandled critical extensions list")
		}

		// Build certificate pool for chain validation
		for _, cert := range certs {
			if cert.Subject.String() == cert.Issuer.String() {
				roots.AddCert(cert)
				continue
			} else {
				intermediates.AddCert(cert)
			}
		}
		opts := x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
		}

		// Certificate chain validation for leaf
		chains, err := leafcert.Verify(opts)
		if err != nil {
			// TODO: Fail the test with Errorf here once we expect it to pass.
			t.Logf("Could not establish a Certificate Chain: %v", err)
		}

		// Log certificate chains linked to leaf
		for _, chain := range chains {
			for i, cert := range chain {
				t.Logf("%d %s", i, (*cert).Subject)
			}
		}

		// Validate signature of all certificates
		all_certs := append(certs, leafcert)
		err_map := validateSignature(all_certs)
		if len(err_map) > 0 {
			for cert_name, msg := range err_map {
				// TODO: Fail the test when the certificate is expected to pass
				// At present moment signature validation ails for cert returned by CertifyKey command.
				t.Logf("Certificate \"%s\" signature validation failed \"%s\"", cert_name, msg)
			}
			t.Logf("Found certificates with mismatching signature")
		}

		t.Logf("DPE leaf certificate chain validation is done")

	} else {
		// Remove unhandled critical extensions reported by x509 but defined in spec
		unknown_ext_map := removeUnhandledCriticalExtensions(certs)
		if len(unknown_ext_map) > 0 {
			for cert_name, ext := range unknown_ext_map {
				t.Errorf("Certificate \"%s\" has unknown UnhandledCriticalExtension \"%s\"", cert_name, ext)
			}
			t.Fatalf("Cannot proceed certificate chain validation with non-empty unhahndled critical extensions list")
		}

		// Build certificate pool for chain validation
		for _, cert := range certs {
			if cert.Subject.String() == cert.Issuer.String() {
				roots.AddCert(cert)
				continue
			} else {
				intermediates.AddCert(cert)
			}
		}
		opts := x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
		}

		// Certificate chain validation for each intermediate certificate
		for _, cert := range certs {
			chains, err := cert.Verify(opts)
			if err != nil {
				// TODO: Fail the test with Errorf here once we expect it to pass.
				t.Logf("Could not establish a Certificate Chain: %v for %s", err, cert.Subject)
			}

			// Log certificate chains linked to each cetificate in chain
			for _, chain := range chains {
				for i, cert := range chain {
					t.Logf("%d %s", i, (*cert).Subject)
				}
			}
		}
		// Validate signature of all certificates
		err_map := validateSignature(certs)
		if len(err_map) > 0 {
			for cert_name, msg := range err_map {
				t.Errorf("Certificate \"%s\" signature validation failed \"%s\"", cert_name, msg)
			}
			t.Fatalf("Found certificates with mismatching signature")
		}

		t.Logf("Intermediate certificates chain validation is done")
	}
}
