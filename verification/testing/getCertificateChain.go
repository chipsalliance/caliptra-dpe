// Licensed under the Apache-2.0 license

package verification

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/chipsalliance/caliptra-dpe/verification/client"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	zx509 "github.com/zmap/zcrypto/x509"
	zlint "github.com/zmap/zlint/v3"
	"github.com/zmap/zlint/v3/lint"
)

// TestGetCertificateChain tests calling GetCertificateChain
func TestGetCertificateChain(d client.TestDPEInstance, client client.DPEClient, t *testing.T) {
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
			// Certs in the Caliptra cert chain fail this lint currently.
			// We will need to truncate the serial numbers for those certs and
			// then enable this lint.
			"e_subject_dn_serial_number_max_length",
			// Firmware certificates don't get revocated, so there is no need
			// for a CRSL to be specified in the CA certificate.
			"w_distribution_point_missing_ldap_or_uri",
			// Authority Information Access for CA can also be an HTTPS URI.
			"w_ext_aia_access_location_missing",
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
			t.Fatalf("Certificate lint failed!")
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
	for i, cert := range certChain {
		if cert.SignatureAlgorithm.String() == "2.16.840.1.101.3.4.3.19" || cert.PublicKeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
			t.Logf("[DEBUG]: Performing manual verification for ML-DSA Cert[%d]", i)
			// Manual verification for ML-DSA
			var issuer *x509.Certificate
			if i == 0 {
				if cert.Subject.String() == cert.Issuer.String() {
					issuer = cert
				} else {
					t.Logf("[DEBUG]: Cert[0] is not self-signed (Issuer: %s), trusting as root anchor without signature verification", cert.Issuer)
					continue
				}
			} else {
				issuer = certChain[i-1]
			}

			var spki struct {
				Algorithm        pkix.AlgorithmIdentifier
				SubjectPublicKey asn1.BitString
			}
			if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &spki); err != nil {
				t.Errorf("[ERROR]: Failed to parse issuer SPKI for Cert[%d]: %v", i, err)
				continue
			}

			var pk mldsa87.PublicKey
			if err := pk.UnmarshalBinary(spki.SubjectPublicKey.Bytes); err != nil {
				t.Errorf("[ERROR]: Failed to parse issuer ML-DSA public key for Cert[%d]: %v", i, err)
				continue
			}

			if !mldsa87.Verify(&pk, cert.RawTBSCertificate, nil, cert.Signature) {
				t.Errorf("[ERROR]: ML-DSA Certificate Signature Verification failed for Cert[%d]", i)
			}
			continue
		}

		chains, err := cert.Verify(opts)
		if err != nil {
			t.Errorf("[ERROR]: Error in Certificate Chain of %s: %s", cert.Subject, err.Error())
		}

		// Log certificate chains linked to each certificate in chain
		if len(chains) != 1 {
			t.Errorf("[ERROR]: validateCertChain certificate chain is empty")
		}
	}
}
