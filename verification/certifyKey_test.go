// Licensed under the Apache-2.0 license

package verification

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"log"
	"reflect"
	"testing"
	"time"

	zx509 "github.com/zmap/zcrypto/x509"
	zlint "github.com/zmap/zlint/v3"
	"github.com/zmap/zlint/v3/lint"

	"golang.org/x/exp/slices"
)

type CertifyKeyFlag int

const (
	// RESERVED_0 CertifyKeyFlag = 31
	AddIsCA CertifyKeyFlag = 30
	// RESERVED_1 CertifyKeyFlag     = 29:0   for future use

)

// This file is used to test the certify key command by using a simulator/emulator
var (
	OidExtensionAuthorityKeyIdentifier = asn1.ObjectIdentifier{2, 5, 29, 35}
	OidExtensionBasicConstraints       = asn1.ObjectIdentifier{2, 5, 29, 19}
	OidExtensionExtKeyUsage            = asn1.ObjectIdentifier{2, 5, 29, 37}
	OidExtensionTcgDiceUeid            = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 4}
	OidExtensionTcgDiceMultiTcbInfo    = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 5}
	OidExtensionTcgDiceKpIdentityInit  = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 100, 6}
	OidExtensionTcgDiceKpIdentityLoc   = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 100, 7}
	OidExtensionTcgDiceKpAttestInit    = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 100, 8}
	OidExtensionTcgDiceKpAttestLoc     = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 100, 9}
	OidExtensionTcgDiceKpAssertInit    = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 100, 10}
	OidExtensionTcgDiceKpAssertLoc     = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 100, 11}
	OidExtensionTcgDiceKpEca           = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 100, 12}
)

var TcgDiceCriticalExtensions = [...]string{
	OidExtensionTcgDiceMultiTcbInfo.String(),
	OidExtensionTcgDiceUeid.String(),
	OidExtensionTcgDiceKpIdentityLoc.String(),
	OidExtensionTcgDiceKpAttestLoc.String(),
}

// tcg-dice-Ueid OBJECT IDENTIFIER ::= {tcg-dice 4}
//
//	TcgUeid ::== SEQUENCE {
//			ueid OCTET STRING
//	}
type TcgUeidExtension struct {
	Ueid []byte `asn1:"ueid,implicit"`
}

// tcg-dice-MultiTcbInfo OBJECT IDENTIFIER ::= {tcg-dice 5}
// DiceTcbInfoSeq ::= SEQUENCE SIZE (1..MAX) OF DiceTcbInfo
//
// tcg-dice-TcbInfo OBJECT IDENTIFIER ::= {tcg-dice 1}
//
// DiceTcbInfo 	::== SEQUENCE {
// 		vendor		[0] IMPLICIT UTF8String OPTIONAL,
// 		model 		[1] IMPLICIT UTF8String OPTIONAL,
// 		version 	[2] IMPLICIT UTF8String OPTIONAL,
// 		svn 		[3] IMPLICIT INTEGER OPTIONAL,
// 		layer 		[4] IMPLICIT INTEGER OPTIONAL,
// 		index 		[5] IMPLICIT INTEGER OPTIONAL,
// 		fwids 		[6] IMPLICIT FWIDLIST OPTIONAL,
// 		flags 		[7] IMPLICIT OperationalFlags OPTIONAL,
//		vendorInfo 	[8] IMPLICIT OCTET STRING OPTIONAL,
// 		type 		[9] IMPLICIT OCTET STRING OPTIONAL
// }
//
// FWIDLIST ::== SEQUENCE SIZE (1..MAX) OF FWID
// FWID ::== SEQUENCE {
// 		hashAlg 	OBJECT IDENTIFIER,
// 		digest 		OCTET STRING
// }
//
// OperationalFlags ::= BIT STRING {
// 		notConfigured (0),
// 		notSecure (1),
// 		recovery (2),
//  	debug (3)
// }

// type Fwid struct {
// 	HashAlg asn1.ObjectIdentifier `asn1:"hashAlg"`
// 	Digest  []byte                `asn1:"digest"`
// }

// type DiceTcbInfo struct {
// 	Vendor     string         `asn1:"vendor,tag:0,implicit,optional"`
// 	Model      string         `asn1:"model,tag:1,implicit,optional"`
// 	Version    string         `asn1:"model,tag:2,implicit,optional"`
// 	SVN        int            `asn1:"svn,tag:3,implicit,optional"`
// 	Layer      int            `asn1:"layer,tag:4,implicit,optional"`
// 	Index      int            `asn1:"index,tag:5,implicit,optional"`
// 	Fwids      []Fwid         `asn1:"fwids,tag:6,implicit,optional"`
// 	Flags      asn1.BitString `asn1:"flags,tag:7,implicit,optional"`
// 	VendorInfo []byte         `asn1:"vendorInfo,tag:8,implicit,optional"`
// 	Type       []byte         `asn1:"type,tag:9,implicit,optional"`
// }

// type TcgMultiTcbInfo struct {
// 	DiceTcbInfos []DiceTcbInfo `asn1:"sequence"`
// }

type DiceTcbInfo struct {
	Vendor     string         `asn1:"tag:0,implicit,optional"`
	Model      string         `asn1:"tag:1,implicit,optional"`
	Version    string         `asn1:"tag:2,implicit,optional"`
	SVN        int            `asn1:"tag:3,implicit,optional"`
	Layer      int            `asn1:"tag:4,implicit,optional"`
	Index      int            `asn1:"tag:5,implicit,optional"`
	Fwids      []Fwid         `asn1:"tag:6,implicit,optional"`
	Flags      asn1.BitString `asn1:"tag:7,implicit,optional"`
	VendorInfo []byte         `asn1:"tag:8,implicit,optional"`
	Type       []byte         `asn1:"tag:9,implicit,optional"`
}

// type DiceTcbSeq []DiceTcbInfo

//	type TcgMultiTcbInfo struct {
//		DiceTcbInfos []DiceTcbInfo `asn1:"sequence"`
//	}
type Fwid struct {
	HashAlg asn1.ObjectIdentifier `asn1:"hashAlg"`
	Digest  []byte                `asn1:"digest"`
}

func TestCertifyKey(t *testing.T) {

	supportNeeded := []string{"AutoInit", "X509"}
	instance, err := GetTestTarget(supportNeeded)
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

	supportNeeded := []string{"AutoInit", "Simulation", "X509"}
	instance, err := GetTestTarget(supportNeeded)
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
// unknownExtnMap collects extensions unknown to both x59 and the DICE certificate profiles spec.
// positive case expects the unknownExtnMap to be empty.
func removeTcgDiceCriticalExtensions(t *testing.T, certs []*x509.Certificate) {
	t.Helper()
	unknownExtnMap := map[string][]string{}
	for _, cert := range certs {
		if len(cert.UnhandledCriticalExtensions) > 0 {
			unknownExtns := []string{}
			for _, extn := range cert.UnhandledCriticalExtensions {
				if !slices.Contains(TcgDiceCriticalExtensions[:], extn.String()) {
					unknownExtns = append(unknownExtns, extn.String())
				}
			}

			if len(unknownExtnMap) == 0 {
				cert.UnhandledCriticalExtensions = []asn1.ObjectIdentifier{}
			} else {
				unknownExtnMap[cert.Subject.String()] = unknownExtns
			}
		}
	}
	// The error details in thi map will be logged
	if len(unknownExtnMap) > 0 {
		for certSubject, ext := range unknownExtnMap {
			t.Errorf("Certificate \"%s\" has unhandled critical extension \"%s\"", certSubject, ext)
		}
		t.Errorf("Cannot proceed certificate chain validation with non-empty unhandled critical extensions list")
	}
}

// A tcg-dice-Ueid extension MUST be added
// This SHALL be populated by the LABEL input parameter to CertifyKey
// The extension SHOULD be marked as critical
func checkCertifyKeyTcgUeidExtension(t *testing.T, c *x509.Certificate, label []byte) {
	t.Helper()

	isFound := false
	// Check UEID extension
	for _, ext := range c.Extensions {
		if ext.Id.Equal(OidExtensionTcgDiceUeid) {
			isFound = true
			if !ext.Critical {
				t.Errorf("tcg-dice-Ueid extension is NOT marked as CRITICAL")
			}
			var ueid TcgUeidExtension = TcgUeidExtension{}
			_, err := asn1.Unmarshal(ext.Value, &ueid)
			if err != nil {
				t.Errorf("Error encountered while unmarshalling value of UEID extension, %s", err.Error())
			}

			t.Logf("Value of UEID extension is %s", ueid.Ueid)
			t.Logf("Value of Label passed as input parameter is %s", label)
			if !reflect.DeepEqual(ueid.Ueid, label) {
				// Ueid extn value doen not match the label
				t.Errorf("tcg-dice-Ueid value does not match with the \"Label\" passed in CertifyKeyRequest")
			} else {
				t.Logf("tcg-dice-Ueid value matches with the \"Label\" passed in CertifyKeyRequest")
			}
			break
		}
	}
	if !isFound {
		t.Errorf("tcg-dice-Ueid extension is missing")
	}
}

// A tcg-dice-MultiTcbInfo extension.
// This extension SHOULD be marked as critical.
func checkCertifyKeyMultiTcbInfoExtension(t *testing.T, c *x509.Certificate) {
	t.Helper()

	// Check MultiTcbInfo Extension
	//tcg-dice-MultiTcbInfo extension
	var multiTcbInfo DiceTcbInfo
	for _, ext := range c.Extensions {
		if ext.Id.Equal(OidExtensionTcgDiceMultiTcbInfo) { // OID for Tcg Dice MultiTcbInfo
			if !ext.Critical {
				t.Errorf("TCG DICE MultiTcbInfo extension is not marked as CRITICAL")
			}
			_, err := asn1.Unmarshal(ext.Value, &multiTcbInfo)
			if err != nil {
				// multiTcb info is not provided in leaf
				t.Errorf("Failed to unmarshal MultiTcbInfo field: %v", err)
			}
			break
		}
	}
}

// Check whether certificate extended key usage is as per spec
// OID for ExtendedKeyUsage Extension: 2.5.29.37
// The ExtendedKeyUsage extension SHOULD be marked as critical
// If IsCA = true, the extension SHOULD contain tcg-dice-kp-eca
// If IsCA = false, the extension SHOULD contain tcg-dice-kp-attestLoc
func checkCertifyKeyExtendedKeyUsages(t *testing.T, c *x509.Certificate) {
	t.Helper()

	extKeyUsage := []asn1.ObjectIdentifier{}

	for _, ext := range c.Extensions {
		if ext.Id.Equal(OidExtensionExtKeyUsage) { // OID for ExtKeyUsage extension
			// Extract the OID value from the extension
			_, err := asn1.Unmarshal(ext.Value, &extKeyUsage)
			if err != nil {
				t.Errorf("Failed to unmarshal the Extended Key Usage extension: %v", err)
				continue
			}

			if !ext.Critical {
				t.Errorf("The Extended Key Usage extension IS NOT CRITICAL, MUST BE CRITICAL")
			} else {
				t.Logf("The Extended Key Usage extension is marked CRITICAL")
			}
			break
		}
	}

	if len(extKeyUsage) == 0 {
		t.Errorf("The Extended Key Usage extension is empty")
	}

	// Iterate over the OIDs in the ExtKeyUsage extension
	isExtendedKeyUsageValid := false
	var expectedKeyUsage asn1.ObjectIdentifier
	expectedKeyUsageName := ""
	if c.IsCA {
		expectedKeyUsage = OidExtensionTcgDiceKpEca
		expectedKeyUsageName = "tcg-dice-kp-eca"
	} else {
		expectedKeyUsage = OidExtensionTcgDiceKpAttestLoc
		expectedKeyUsageName = "tcg-dice-kp-attest-loc"
	}

	for _, oid := range extKeyUsage {
		if oid.Equal(expectedKeyUsage) {
			isExtendedKeyUsageValid = true
			t.Logf("Certificate has IsCA: %v and contains specified key usage: %s", c.IsCA, expectedKeyUsageName)
			break
		}
	}
	if !isExtendedKeyUsageValid {
		t.Errorf("Certificate has IsCA: %v  and does not contain specified key usage: %s", c.IsCA, expectedKeyUsageName)
	}
}

// Check for KeyUsage Extension as per spec
// If IsCA = true, KeyUsage extension MUST contain DigitalSignature and KeyCertSign
// If IsCA = false, KeyUsage extension MUST contain  only DigitalSignature
func checkCertifyKeyExtensions(t *testing.T, c *x509.Certificate) {
	t.Helper()

	//Check for keyusage extension
	var allowedKeyUsages x509.KeyUsage
	if c.IsCA {
		allowedKeyUsages = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	} else {
		allowedKeyUsages = x509.KeyUsageDigitalSignature
	}

	certKeyUsageList := getKeyUsageNames(c.KeyUsage)
	allowedKeyUsageList := getKeyUsageNames(allowedKeyUsages)

	if c.KeyUsage == allowedKeyUsages {
		t.Logf("Certificate has IsCA: %v and has the expected key usage %v ", c.IsCA, certKeyUsageList)
	} else {
		t.Errorf("Certificate has IsCA: %v and has got %v but want %v ", c.IsCA, certKeyUsageList, allowedKeyUsageList)
	}

}

// Validate basic constraints in certificate returned by CertifyKey command
// against the flag set for input parameter.
// The BasicConstraints extension MUST be included
// If CertifyKey AddIsCA is set, IsCA MUST be set to true.
// If CertifyKey AddIsCA is NOT set, IsCA MUST be set to false
func checkCertifyKeyBasicConstraints(t *testing.T, c *x509.Certificate, flags uint32) {
	t.Helper()

	flagsBuf := &bytes.Buffer{}
	binary.Write(flagsBuf, binary.LittleEndian, flags)

	flagIsCA := extractFlagBit(int(AddIsCA), uint32(flags))

	if flagIsCA == c.IsCA {
		t.Logf("ADD_IS_CA is set to %v and the basic constraint IsCA is set to %v", flagIsCA, c.IsCA)
	} else {
		t.Errorf("ADD_IS_CA is set to %v but the basic constraint IsCA is set to %v", flagIsCA, c.IsCA)
	}
}

// Validate X509 fields in certificate returned by CertifyKey command.
func validateCertifyKeyCert(t *testing.T, c *x509.Certificate, flags uint32, label []byte) {
	t.Helper()

	// Check for basic constraints extension
	checkCertifyKeyBasicConstraints(t, c, flags)

	// Check key usage extensions - DigitalSignature, KeyCertSign
	checkCertifyKeyExtensions(t, c)

	// Check extended key usage extensions
	checkCertifyKeyExtendedKeyUsages(t, c)

	// Check critical TCG extensions
	// Check UEID extension
	checkCertifyKeyTcgUeidExtension(t, c, label)

	// Check MultiTcbInfo Extension
	checkCertifyKeyMultiTcbInfoExtension(t, c)
}

func checkCertificateStructure(t *testing.T, certBytes []byte) *x509.Certificate {
	t.Helper()
	failed := false

	var x509Cert *x509.Certificate
	var err error

	// Check whether certificate is DER encoded.
	if x509Cert, err = x509.ParseCertificate(certBytes); err != nil {
		t.Fatalf("Could not parse certificate using crypto/x509: %v", err)
	}

	// Parse the cert with zcrypto so we can lint it.
	cert, err := zx509.ParseCertificate(certBytes)
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
			Bytes: certBytes,
		})))
		t.Logf("Offending certificate (DER):\n%x", certBytes)
	}
	return x509Cert
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

	certifyKeyReq := []CertifyKeyReq[SHA256Digest]{
		{
			ContextHandle: [16]byte{0},
			Flags:         0,
			Label:         [32]byte{},
			Format:        CertifyKeyX509,
		},
		{
			ContextHandle: [16]byte{0},
			Flags:         1073741824, // Set the 31st bit: 01000000 00000000 00000000 00000000
			Label:         [32]byte{},
			Format:        CertifyKeyX509,
		},
	}

	for _, r := range certifyKeyReq {
		// Get DPE leaf certificate from CertifyKey
		certifyKeyResp, err := client.CertifyKey(&r)
		if err != nil {
			t.Fatalf("Could not certify key: %v", err)
		}

		// Get root and intermediate certificates to validate certificate chain of leaf cert
		getCertificateChainResp, err := client.GetCertificateChain()
		if err != nil {
			t.Fatalf("Could not get Certificate Chain: %v", err)
		}

		leafCertBytes := certifyKeyResp.Certificate
		certChainBytes := getCertificateChainResp.CertificateChain

		// Run X.509 linter on full certificate chain and file issues for errors
		leafCert := checkCertificateStructure(t, leafCertBytes)
		t.Logf("Leaf certificate is DER encoded")

		certChain := checkCertificateChain(t, certChainBytes)
		t.Logf("Certificate chain is DER encoded")

		// Validate that all X.509 fields conform with the format defined in the DPE iRoT profile
		validateCertifyKeyCert(t, leafCert, uint32(r.Flags), r.Label[:])

		// Ensure full certificate chain has valid signatures
		// This also checks certificate lifetime, signatures as part of cert chain validation
		validateCertChain(t, certChain, leafCert)

		// TODO: When DeriveChild is implemented, call it here to add more TCIs and call CertifyKey again.
	}
}

// Build certificate chain and calls to validateSignature on each chain.
func validateCertChain(t *testing.T, certChain []*x509.Certificate, leafCert *x509.Certificate) {
	t.Helper()
	var certsToProcess []*x509.Certificate
	if leafCert != nil {
		t.Log("Validating leaf certificate chain...")
		certsToProcess = []*x509.Certificate{leafCert}
	} else {
		t.Log("Validating intermediate certificates chains...")
		certsToProcess = certChain
	}

	// Remove unhandled critical extensions reported by x509 but defined in spec
	t.Log("Checking for unhandled critical certificate extensions unknown to DPE certificates profile spec...")
	removeTcgDiceCriticalExtensions(t, certsToProcess)

	// Build verify options
	opts := buildVerifyOptions(t, certChain)

	if leafCert != nil {
		// Certificate chain validation for leaf
		chains, err := leafCert.Verify(opts)
		if err != nil {
			// Certificate chain cannot be built from leaf to root
			t.Errorf("Error in certificate chain %s: ", err.Error())
		}

		// Log certificate chains linked to leaf
		for _, chain := range chains {
			for i, cert := range chain {
				t.Logf("%d %s", i, (*cert).Subject)
			}

		}

		// This indicates that signature validation found no errors in the DPE leaf cert chain
		t.Logf("DPE leaf certificate chain validation is done")

	} else {
		// Certificate chain validation for each intermediate certificate
		for _, cert := range certChain {
			chains, err := cert.Verify(opts)
			if err != nil {
				t.Errorf("Error in Certificate Chain of %s: %s", cert.Subject, err.Error())
			}

			// Log certificate chains linked to each cetificate in chain
			for _, chain := range chains {
				for i, cert := range chain {
					t.Logf("%d %s", i, (*cert).Subject)
				}
			}
		}

		// This indicates that signature validation found no errors each cert
		// chain of intermediate certificates
		t.Logf("Intermediate certificates chain validation is done")
	}
}

func buildVerifyOptions(t *testing.T, certChain []*x509.Certificate) x509.VerifyOptions {
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()

	if certChain[0].Subject.String() != certChain[0].Issuer.String() {
		t.Errorf("Found a non-root certificate in beginning of certificate chain returned by GetCertificateChain.")
		t.Logf("Root certificate is expected to be in the beginning of the chain, the rest are expected to be intermediates.")
	} else {
		roots.AddCert(certChain[0])
	}

	for _, cert := range certChain[1:] {
		if cert.Subject.String() == cert.Issuer.String() {
			t.Errorf("Found a Root certificate in middle of certificate chain returned by GetCertificateChain.")
			t.Logf("Root certificate is expected to be the first certificate in the chain, the rest are expected to be intermediates.")
			continue
		}
		intermediates.AddCert(cert)
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now().UTC(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, // Is this correct?
	}

	return opts
}

func extractFlagBit(pos int, flags uint32) bool {
	var mask uint32 = (1 << pos)
	return (flags & mask) > 0
}

func getKeyUsageNames(keyUsage x509.KeyUsage) []string {
	keyUsageNames := []string{}

	if keyUsage&x509.KeyUsageDigitalSignature == 1 {
		keyUsageNames = append(keyUsageNames, "DigitalSignature")
	}

	if keyUsage&x509.KeyUsageContentCommitment == 1 {
		keyUsageNames = append(keyUsageNames, "ContentCommitment")
	}

	if keyUsage&x509.KeyUsageKeyEncipherment == 1 {
		keyUsageNames = append(keyUsageNames, "KeyEncipherment")
	}

	if keyUsage&x509.KeyUsageDataEncipherment == 1 {
		keyUsageNames = append(keyUsageNames, "DataEncipherment")
	}

	if keyUsage&x509.KeyUsageKeyAgreement == 1 {
		keyUsageNames = append(keyUsageNames, "KeyAgreement")
	}

	if keyUsage&x509.KeyUsageCertSign == 1 {
		keyUsageNames = append(keyUsageNames, "CertSign")
	}

	if keyUsage&x509.KeyUsageCRLSign == 1 {
		keyUsageNames = append(keyUsageNames, "CRLSign")
	}

	if keyUsage&x509.KeyUsageEncipherOnly == 1 {
		keyUsageNames = append(keyUsageNames, "EncipherOnly")
	}

	if keyUsage&x509.KeyUsageDecipherOnly == 1 {
		keyUsageNames = append(keyUsageNames, "DecipherOnly")
	}

	return keyUsageNames
}
