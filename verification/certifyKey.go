// Licensed under the Apache-2.0 license

package verification

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"reflect"
	"testing"
	"time"

	zx509 "github.com/zmap/zcrypto/x509"
	zlint "github.com/zmap/zlint/v3"
	"github.com/zmap/zlint/v3/lint"

	"golang.org/x/exp/slices"
)

// This file is used to test the certify key command.
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
}

var TcgDiceExtendedKeyUsages = [...]string{
	OidExtensionTcgDiceKpIdentityLoc.String(),
	OidExtensionTcgDiceKpAttestLoc.String(),
}

// tcg-dice-Ueid OBJECT IDENTIFIER ::= {tcg-dice 4}
//
//	TcgUeid ::== SEQUENCE {
//			ueid OCTET STRING
//	}
type TcgUeidExtension struct {
	Ueid []uint8 `asn1:"ueid,implicit"`
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
// 		type 		[9] IMPLICIT OCTET STRING OPTIONAL,
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

type Fwid struct {
	HashAlg asn1.ObjectIdentifier
	Digest  []byte
}

type DiceTcbInfo struct {
	Vendor     string          `asn1:"optional,tag:0,utf8"`
	Model      string          `asn1:"optional,tag:1,utf8"`
	Version    string          `asn1:"optional,tag:2,utf8"`
	SVN        int             `asn1:"optional,tag:3"`
	Layer      int             `asn1:"optional,tag:4"`
	Index      int             `asn1:"optional,tag:5"`
	Fwids      []Fwid          `asn1:"optional,tag:6"`
	Flags      OperationalFlag `asn1:"optional,tag:7"`
	VendorInfo []byte          `asn1:"optional,tag:8"`
	Type       []byte          `asn1:"optional,tag:9"`
}

type OperationalFlag int

const (
	NotConfigured OperationalFlag = iota
	NotSecure
	Debug
	Recovery
)

type TcgMultiTcbInfo = []DiceTcbInfo

func TestCertifyKey(d TestDPEInstance, c DPEClient, t *testing.T) {
	testCertifyKey(d, c, t, false)
}

func TestCertifyKey_SimulationMode(d TestDPEInstance, c DPEClient, t *testing.T) {
	testCertifyKey(d, c, t, true)
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
	// The error details in this map will be logged
	if len(unknownExtnMap) > 0 {
		for certSubject, ext := range unknownExtnMap {
			t.Errorf("[ERROR]: Certificate \"%s\" has unhandled critical extension \"%s\"", certSubject, ext)
		}
		t.Errorf("[ERROR]: Certificate chain validation will fail with non-empty unhandled critical extensions list")
	}
}

func removeTcgDiceExtendedKeyUsages(t *testing.T, certs []*x509.Certificate) {
	t.Helper()
	unknownKeyUsagesMap := map[string][]string{}
	for _, cert := range certs {
		if len(cert.UnknownExtKeyUsage) > 0 {
			unknownKeyUsages := []string{}
			for _, eku := range cert.UnknownExtKeyUsage {
				if !slices.Contains(TcgDiceExtendedKeyUsages[:], eku.String()) {
					unknownKeyUsages = append(unknownKeyUsages, eku.String())
				}
			}

			if len(unknownKeyUsagesMap) == 0 {
				cert.UnknownExtKeyUsage = []asn1.ObjectIdentifier{}
			} else {
				unknownKeyUsagesMap[cert.Subject.String()] = unknownKeyUsages
			}
		}
	}
	// The error details in this map will be logged
	if len(unknownKeyUsagesMap) > 0 {
		for certSubject, ext := range unknownKeyUsagesMap {
			t.Errorf("[ERROR]: Certificate \"%s\" has unknown extended key usages \"%s\"", certSubject, ext)
		}
		t.Errorf("[ERROR]: Certificate chain validation will fail with non-empty unknown extended key usages list")
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
				t.Errorf("[ERROR]: tcg-dice-Ueid extension is NOT marked as CRITICAL")
			}
			var ueid TcgUeidExtension = TcgUeidExtension{}
			_, err := asn1.Unmarshal(ext.Value, &ueid)
			if err != nil {
				t.Errorf("[ERROR]: Error encountered while unmarshalling value of UEID extension, %s", err.Error())
			}

			if !reflect.DeepEqual(ueid.Ueid, label) {
				// Ueid extn value doen not match the label
				t.Errorf("[ERROR]: tcg-dice-Ueid value does not match with the \"Label\" passed in CertifyKeyRequest")
			}
			break
		}
	}
	if !isFound {
		t.Errorf("[ERROR]: tcg-dice-Ueid extension is missing")
	}
}

// A tcg-dice-MultiTcbInfo extension.
// This extension SHOULD be marked as critical.
func checkCertifyKeyMultiTcbInfoExtension(t *testing.T, c *x509.Certificate) (TcgMultiTcbInfo, error) {
	t.Helper()
	var multiTcbInfo TcgMultiTcbInfo
	var err error

	// Check MultiTcbInfo Extension
	//tcg-dice-MultiTcbInfo extension
	for _, ext := range c.Extensions {
		if ext.Id.Equal(OidExtensionTcgDiceMultiTcbInfo) { // OID for Tcg Dice MultiTcbInfo
			if !ext.Critical {
				t.Errorf("[ERROR]: TCG DICE MultiTcbInfo extension is not marked as CRITICAL")
			}
			_, err = asn1.Unmarshal(ext.Value, &multiTcbInfo)
			if err != nil {
				// multiTcb info is not provided in leaf
				t.Errorf("[ERROR]: Failed to unmarshal MultiTcbInfo field: %v", err)
			}
			break
		}
	}
	return multiTcbInfo, err
}

// Check whether certificate extended key usage is as per spec
// OID for ExtendedKeyUsage Extension: 2.5.29.37
// The ExtendedKeyUsage extension SHOULD be marked as critical
// If IsCA = true, the extension SHOULD contain tcg-dice-kp-eca
// If IsCA = false, the extension SHOULD contain tcg-dice-kp-attestLoc
func checkCertifyKeyExtendedKeyUsages(t *testing.T, c *x509.Certificate) (*TcgMultiTcbInfo, error) {
	t.Helper()
	var multiTcbInfo *TcgMultiTcbInfo
	var err error

	extKeyUsage := []asn1.ObjectIdentifier{}

	for _, ext := range c.Extensions {
		if ext.Id.Equal(OidExtensionExtKeyUsage) { // OID for ExtKeyUsage extension
			// Extract the OID value from the extension
			_, err := asn1.Unmarshal(ext.Value, &extKeyUsage)
			if err != nil {
				t.Errorf("[ERROR]: Failed to unmarshal the Extended Key Usage extension: %v", err)
				continue
			}

			if !ext.Critical {
				t.Errorf("[ERROR]: The Extended Key Usage extension IS NOT CRITICAL, MUST BE CRITICAL")
			}
			break
		}
	}

	if len(extKeyUsage) == 0 {
		t.Errorf("[ERROR]: The Extended Key Usage extension is empty")
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
			break
		}
	}
	if !isExtendedKeyUsageValid {
		t.Errorf("[ERROR]: Certificate has IsCA: %v  and does not contain specified key usage: %s", c.IsCA, expectedKeyUsageName)
	}
	return multiTcbInfo, err
}

// Check for KeyUsage Extension as per spec
// If IsCA = true, KeyUsage extension MUST contain DigitalSignature and KeyCertSign
// If IsCA = false, KeyUsage extension MUST contain  only DigitalSignature
func checkCertifyKeyExtensions(t *testing.T, c *x509.Certificate) {
	t.Helper()

	//Check for keyusage extension
	var allowedKeyUsages x509.KeyUsage
	if c.IsCA {
		allowedKeyUsages = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	} else {
		allowedKeyUsages = x509.KeyUsageDigitalSignature
	}

	certKeyUsageList := getKeyUsageNames(c.KeyUsage)
	allowedKeyUsageList := getKeyUsageNames(allowedKeyUsages)
	if c.KeyUsage != allowedKeyUsages {
		t.Errorf("[ERROR]: Certificate has IsCA: %v and has got %v but want %v ", c.IsCA, certKeyUsageList, allowedKeyUsageList)
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

	flagIsCA := uint32(CertifyAddIsCA)&flags != 0
	if flagIsCA != c.IsCA {
		t.Errorf("[ERROR]: ADD_IS_CA is set to %v but the basic constraint IsCA is set to %v", flagIsCA, c.IsCA)
	}
}

// Validate X509 fields in certificate returned by CertifyKey command.
func validateCertifyKeyCert(t *testing.T, c *x509.Certificate, flags uint32, label []byte) {
	t.Helper()

	// Check for basic constraints extension
	checkCertifyKeyBasicConstraints(t, c, flags)

	// Check key usage extensions - DigitalSignature, CertSign
	checkCertifyKeyExtensions(t, c)

	// Check extended key usage extensions
	checkCertifyKeyExtendedKeyUsages(t, c)

	// Check critical UEID and Multi Tcb Info TCG extensions
	// Check UEID extension
	checkCertifyKeyTcgUeidExtension(t, c, label)

	// Check MultiTcbInfo Extension structure
	checkCertifyKeyMultiTcbInfoExtension(t, c)
}

func checkCertificateStructure(t *testing.T, certBytes []byte) *x509.Certificate {
	t.Helper()
	failed := false

	var x509Cert *x509.Certificate
	var err error

	// Check whether certificate is DER encoded.
	if x509Cert, err = x509.ParseCertificate(certBytes); err != nil {
		t.Fatalf("[FATAL]: Could not parse certificate using crypto/x509: %v", err)
	}

	// Parse the cert with zcrypto so we can lint it.
	cert, err := zx509.ParseCertificate(certBytes)
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
		t.Logf("[LINT %s] %s: %s%s (%s)", level, l.Source, details, l.Description, l.Citation)
		failed = true
	}

	if failed {
		// Dump the cert in PEM and hex for use with various tools
		t.Logf("[LINT]: Offending certificate: %s\n", cert.Subject.String())
		t.Logf("[LINT]: Offending certificate (PEM):\n%s", (string)(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certBytes,
		})))
	}
	return x509Cert
}

func testCertifyKey(d TestDPEInstance, client DPEClient, t *testing.T, simulation bool) {
	ctx := getContextHandle(d, client, t, simulation)
	if simulation {
		defer client.DestroyContext(ctx, 0)
	}

	type Params struct {
		Label []byte
		Flags CertifyKeyFlags
	}

	profile, err := GetTransportProfile(d)
	if err != nil {
		t.Fatalf("Could not get profile: %v", err)
	}
	digestLen := profile.GetDigestSize()

	seqLabel := make([]byte, digestLen)
	for i, _ := range seqLabel {
		seqLabel[i] = byte(i)
	}

	certifyKeyParams := []Params{
		{Label: make([]byte, digestLen), Flags: CertifyKeyFlags(0)},
		{Label: seqLabel, Flags: CertifyKeyFlags(0)},
	}

	for _, params := range certifyKeyParams {
		// Get DPE leaf certificate from CertifyKey
		certifyKeyResp, err := client.CertifyKey(ctx, params.Label, CertifyKeyX509, params.Flags)
		if err != nil {
			t.Fatalf("[FATAL]: Could not certify key: %v", err)
		}

		// Get root and intermediate certificates to validate certificate chain of leaf cert
		certChainBytes, err := client.GetCertificateChain()
		if err != nil {
			t.Fatalf("[FATAL]: Could not get Certificate Chain: %v", err)
		}

		leafCertBytes := certifyKeyResp.Certificate

		// Run X.509 linter on full certificate chain and file issues for errors
		leafCert := checkCertificateStructure(t, leafCertBytes)
		certChain := checkCertificateChain(t, certChainBytes)

		// Validate that all X.509 fields conform with the format defined in the DPE iRoT profile
		validateCertifyKeyCert(t, leafCert, uint32(params.Flags), params.Label)

		// Ensure full certificate chain has valid signatures
		// This also checks certificate lifetime, signatures as part of cert chain validation
		validateLeafCertChain(t, certChain, leafCert)

		// Reassign handle for simulation mode.
		// However, this does not impact in default mode because
		// same default context handle is returned in default mode.
		ctx = &certifyKeyResp.Handle

		// TODO: When DeriveChild is implemented, call it here to add more TCIs and call CertifyKey again.
	}
}

// Build certificate chain and calls to validateSignature on each chain.
func validateLeafCertChain(t *testing.T, certChain []*x509.Certificate, leafCert *x509.Certificate) {
	t.Helper()
	certsToProcess := []*x509.Certificate{leafCert}

	// Remove unhandled critical extensions reported by x509 but defined in spec
	removeTcgDiceCriticalExtensions(t, certsToProcess)

	// Remove unhandled extended key usages reported by x509 but defined in spec
	removeTcgDiceExtendedKeyUsages(t, certsToProcess)

	// Build verify options
	opts := buildVerifyOptions(t, certChain)

	// Certificate chain validation for leaf
	chains, err := leafCert.Verify(opts)
	if err != nil {
		// Certificate chain cannot be built from leaf to root
		t.Errorf("[ERROR]: Error verifying DPE leaf: %s", err.Error())
	}

	// Log certificate chains linked to leaf
	if len(chains) != 1 {
		t.Errorf("[ERROR]: Unexpected number of cert chains: %d", len(chains))
	}
}

func buildVerifyOptions(t *testing.T, certChain []*x509.Certificate) x509.VerifyOptions {
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()

	// Root certificate is expected to be in the beginning of the chain, the rest are expected to be intermediates.
	roots.AddCert(certChain[0])

	for _, cert := range certChain[1:] {
		if cert.Subject.String() == cert.Issuer.String() {
			t.Errorf("[ERROR]: Found a self-signed certificate in middle of certificate chain returned by GetCertificateChain.")
			continue
		}
		intermediates.AddCert(cert)
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now().UTC(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	return opts
}

func extractFlagBit(pos int, flags uint32) bool {
	var mask uint32 = (1 << pos)
	return (flags & mask) > 0
}

func getKeyUsageNames(keyUsage x509.KeyUsage) []string {
	keyUsageNames := []string{}

	if keyUsage&x509.KeyUsageDigitalSignature != 0 {
		keyUsageNames = append(keyUsageNames, "DigitalSignature")
	}

	if keyUsage&x509.KeyUsageContentCommitment != 0 {
		keyUsageNames = append(keyUsageNames, "ContentCommitment")
	}

	if keyUsage&x509.KeyUsageKeyEncipherment != 0 {
		keyUsageNames = append(keyUsageNames, "KeyEncipherment")
	}

	if keyUsage&x509.KeyUsageDataEncipherment != 0 {
		keyUsageNames = append(keyUsageNames, "DataEncipherment")
	}

	if keyUsage&x509.KeyUsageKeyAgreement != 0 {
		keyUsageNames = append(keyUsageNames, "KeyAgreement")
	}

	if keyUsage&x509.KeyUsageCertSign != 0 {
		keyUsageNames = append(keyUsageNames, "CertSign")
	}

	if keyUsage&x509.KeyUsageCRLSign != 0 {
		keyUsageNames = append(keyUsageNames, "CRLSign")
	}

	if keyUsage&x509.KeyUsageEncipherOnly != 0 {
		keyUsageNames = append(keyUsageNames, "EncipherOnly")
	}

	if keyUsage&x509.KeyUsageDecipherOnly != 0 {
		keyUsageNames = append(keyUsageNames, "DecipherOnly")
	}

	return keyUsageNames
}
