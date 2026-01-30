// Licensed under the Apache-2.0 license

package verification

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"hash"
	"math/big"
	"reflect"
	"testing"
	"time"

	cms "github.com/github/smimesign/ietf-cms"

	"github.com/chipsalliance/caliptra-dpe/verification/client"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	zx509 "github.com/zmap/zcrypto/x509"
	zlint "github.com/zmap/zlint/v3"
	"github.com/zmap/zlint/v3/lint"

	"golang.org/x/exp/slices"
)

// TcgDiceCriticalExtensions are the OIDs of DICE extensions which must be
// marked as critical
var TcgDiceCriticalExtensions = [...]string{
	OidExtensionTcgDiceMultiTcbInfo.String(),
	OidExtensionTcgDiceUeid.String(),
}

// TcgDiceExtendedKeyUsages are the DICE OIDs expected to be present in the DPE
// leaf EKU extension
var TcgDiceExtendedKeyUsages = [...]string{
	OidExtensionTcgDiceKpIdentityLoc.String(),
	OidExtensionTcgDiceKpAttestLoc.String(),
	OidExtensionTcgDiceKpEca.String(),
}

// TcgUeidExtension is tcg-dice-Ueid OBJECT IDENTIFIER ::= {tcg-dice 4}
//
//	TcgUeid ::== SEQUENCE {
//			ueid OCTET STRING
//	}
type TcgUeidExtension struct {
	Ueid []uint8 `asn1:"ueid,implicit"`
}

// Fwid represents a TCG DICE FWID structure
type Fwid struct {
	HashAlg asn1.ObjectIdentifier
	Digest  []byte
}

// DiceTcbInfo represents the following ASN.1 structures
// tcg-dice-MultiTcbInfo OBJECT IDENTIFIER ::= {tcg-dice 5}
// DiceTcbInfoSeq ::= SEQUENCE SIZE (1..MAX) OF DiceTcbInfo
//
// tcg-dice-TcbInfo OBJECT IDENTIFIER ::= {tcg-dice 1}
//
//	DiceTcbInfo 	::== SEQUENCE {
//			vendor		[0] IMPLICIT UTF8String OPTIONAL,
//			model 		[1] IMPLICIT UTF8String OPTIONAL,
//			version 	[2] IMPLICIT UTF8String OPTIONAL,
//			svn 		[3] IMPLICIT INTEGER OPTIONAL,
//			layer 		[4] IMPLICIT INTEGER OPTIONAL,
//			index 		[5] IMPLICIT INTEGER OPTIONAL,
//			fwids 		[6] IMPLICIT FWIDLIST OPTIONAL,
//			flags 		[7] IMPLICIT OperationalFlags OPTIONAL,
//			vendorInfo 	[8] IMPLICIT OCTET STRING OPTIONAL,
//			type 		[9] IMPLICIT OCTET STRING OPTIONAL,
//			integrityRegisters 	[10] IMPLICIT IrList OPTIONAL,
//	}
//
// FWIDLIST ::== SEQUENCE SIZE (1..MAX) OF FWID
//
//	FWID ::== SEQUENCE {
//			hashAlg 	OBJECT IDENTIFIER,
//			digest 		OCTET STRING
//	}
//
//	OperationalFlags ::= BIT STRING {
//			notConfigured (0),
//			notSecure (1),
//			recovery (2),
//	 	debug (3)
//	}
//
// IrList ::= SEQUENCE SIZE (1..MAX) OF IntegrityRegister
// IntegrityRegister ::= SEQUENCE {
//		registerName	[0] IMPLICIT IA5String OPTIONAL,
//		registerNum		[1] IMPLICIT INTEGER OPTIONAL,
//		registerDigests	[2] IMPLICIT FWIDLIST
// }

type DiceTcbInfo struct {
	Vendor             string              `asn1:"optional,tag:0,utf8"`
	Model              string              `asn1:"optional,tag:1,utf8"`
	Version            string              `asn1:"optional,tag:2,utf8"`
	SVN                int                 `asn1:"optional,tag:3"`
	Layer              int                 `asn1:"optional,tag:4"`
	Index              int                 `asn1:"optional,tag:5"`
	Fwids              []Fwid              `asn1:"optional,tag:6"`
	Flags              OperationalFlag     `asn1:"optional,tag:7"`
	VendorInfo         []byte              `asn1:"optional,tag:8"`
	Type               []byte              `asn1:"optional,tag:9"`
	IntegrityRegisters []IntegrityRegister `asn1:"optional,tag:10"`
}

type IntegrityRegister struct {
	RegisterName    string `asn1:"optional,tag:0,ia5"`
	RegisterNum     int    `asn1:"optional,tag:1"`
	RegisterDigests []Fwid `asn1:"optional,tag:2"`
}

// OperationalFlag represents the TCBInfo Operational Flags field
type OperationalFlag int

// TCG spec-defined operational flags
const (
	NotConfigured OperationalFlag = iota
	NotSecure
	Debug
	Recovery
)

// TcgMultiTcbInfo represents a sequence of TCBInfos
type TcgMultiTcbInfo = []DiceTcbInfo

// CertifyKeyParams holds configurable parameters to CertifyKey for test-cases
type CertifyKeyParams struct {
	Label []byte
	Flags client.CertifyKeyFlags
}

// TestCertifyKey tests calling CertifyKey
func TestCertifyKey(d client.TestDPEInstance, c client.DPEClient, t *testing.T) {
	testCertifyKey(d, c, t, false)
}

// TestCertifyKeySimulation tests calling CertifyKey on simulation contexts
func TestCertifyKeySimulation(d client.TestDPEInstance, c client.DPEClient, t *testing.T) {
	testCertifyKey(d, c, t, true)
}

// TestCertifyKeyCsr tests calling CeritifyKey with type = CSR
func TestCertifyKeyCsr(d client.TestDPEInstance, c client.DPEClient, t *testing.T) {
	ctx := getInitialContextHandle(d, c, t, false)

	profile, err := client.GetTransportProfile(d)
	if err != nil {
		t.Fatalf("Could not get profile: %v", err)
	}
	digestLen := profile.GetDigestSize()

	flags := client.CertifyKeyFlags(0)
	label := make([]byte, digestLen)

	// Get DPE leaf certificate from CertifyKey
	certifyKeyResp, err := c.CertifyKey(ctx, label, client.CertifyKeyCsr, flags)
	if err != nil {
		t.Fatalf("[FATAL]: Could not certify key: %v", err)
	}

	wrappedCSR, err := cms.ParseSignedData(certifyKeyResp.Certificate)
	if err != nil {
		t.Fatalf("[FATAL]: Could not unmarshal CSR CMS message: %v", err)
	}

	// Check signature on the CMS message
	certChainBytes, err := c.GetCertificateChain()
	if err != nil {
		t.Fatalf("[FATAL]: Could not get Certificate Chain: %v", err)
	}
	certChain := checkCertificateChain(t, certChainBytes)

	// This library expects the cert to be in the Certificates field but DPE
	// does not populate it. Add it so Verify succeeds.
	//
	// It is still compliant that DPE does not produce the certificate chain.
	// From PKCS#7 section 9.1:
	//		There may also be fewer certificates than necessary, if it is expected that
	//		those verifying the signatures have an alternate means of
	//		obtaining necessary certificates (e.g., from a previous set
	//      of certificates).
	err = wrappedCSR.SetCertificates(certChain)
	if err != nil {
		t.Errorf("[ERROR]: Failed to add certificates to SignedData: %v", err)
	}
	certPool := x509.NewCertPool()
	for _, cert := range certChain {
		certPool.AddCert(cert)
	}

	// Use ExtKeyUsageAny to bypass EKU validation. The standard x509 library doesn't recognize
	// TCG DICE EKUs (tcg-dice-kp-eca, tcg-dice-kp-attestLoc) and provides no mechanism to
	// whitelist custom OIDs. EKU validation is performed separately via removeTcgDiceExtendedKeyUsages(),
	// which ensures only standard x509 EKU values and TCG DICE EKU OIDs are permitted.
	_, err = wrappedCSR.Verify(x509.VerifyOptions{Roots: certPool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		if profile == client.ProfileMldsa87 {
			// TODO(clundin): Verify the CMS wrapper for ML-DSA.
			t.Logf("[WARN]: Skipping CMS wrapper signature verification for ML-DSA (not supported): %v", err)
		} else {
			t.Errorf("[ERROR]: Failed to verify CMS wrapper signature: %v", err)
		}
	}

	content, err := wrappedCSR.GetData()
	if err != nil {
		t.Fatalf("[FATAL]: Could not get CMS content: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(content)
	if err != nil {
		t.Fatalf("[FATAL]: Could not parse CSR: %v", err)
	}

	// Check fields and extensions in the CSR
	isCritical := d.GetSupport().DpeInstanceMarkDiceExtensionsCritical
	checkCertificateExtension(t, csr.Extensions, &label, &certifyKeyResp.Pub, false, certChain[len(certChain)-1].SubjectKeyId, false, isCritical)
	checkPubKey(t, profile, csr.PublicKey, *certifyKeyResp)

	// Check that CSR is self-signed
	err = csr.CheckSignature()
	if err != nil {
		if profile == client.ProfileMldsa87 {
			var pk mldsa87.PublicKey
			// certifyKeyResp.Pub.X contains the raw public key bytes for ML-DSA
			if err := pk.UnmarshalBinary(certifyKeyResp.Pub.X); err != nil {
				t.Errorf("Failed to parse ML-DSA public key from response: %v", err)
			} else {
				if !mldsa87.Verify(&pk, csr.RawTBSCertificateRequest, nil, csr.Signature) {
					t.Errorf("ML-DSA CSR Signature Verification failed")
				} else {
					t.Log("ML-DSA CSR Signature Verified manually")
				}
			}
		} else {
			t.Errorf("[ERROR] CSR is not self-signed: %v", err)
		}
	}
}

// Ignores critical extensions that are unknown to x509 package
// but at least defined in DPE certificate profile specification.
// UnhandledCriticalExtensions may have only custom extensions mentioned in spec
// unknownExtnMap collects extensions unknown to both x509 and the DICE certificate profiles spec.
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

// Ignores extended key usages that are unknown to x509 package
// but at least defined in DPE certificate profile specification.
// UnhandledExtendedKeyUsages may have only custom key usages mentioned in spec
// unknownKeyUsagesMap collects keyusages unknown to both x509 and the DICE certificate profiles spec.
// positive case expects the unknownKeyUsagesMap to be empty.
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
// This SHALL be populated by the LABEL input parameter to CertifyKey or retrieved from DPE Platform
// by DeriveContext.
func checkTcgUeidExtension(t *testing.T, extensions []pkix.Extension, label []byte, isCritical bool) {
	t.Helper()

	ueid, err := getUeid(extensions, isCritical)
	if err != nil {
		t.Errorf("[ERROR]: tcg-dice-Ueid extension is missing: %v", err)
	}

	if !reflect.DeepEqual(ueid.Ueid, label) {
		// Ueid extn value doen not match the label
		t.Errorf("[ERROR]: tcg-dice-Ueid value does not match with the \"Label\". Got %+v but expect %+v", ueid.Ueid, label)
	}
}

// Checks whether certificate extended key usage is as per spec
// OID for ExtendedKeyUsage Extension: 2.5.29.37
// The ExtendedKeyUsage extension SHOULD be marked as critical
// If IsCA = true, the extension SHOULD contain tcg-dice-kp-eca
// If IsCA = false, the extension SHOULD contain tcg-dice-kp-attestLoc
func checkExtendedKeyUsages(t *testing.T, extensions []pkix.Extension, ca bool) {
	t.Helper()

	extKeyUsage, err := getExtendedKeyUsages(extensions)
	if err != nil {
		t.Errorf("[ERROR]: ExtKeyUsage extension is missing: %v", err)
	}

	if len(extKeyUsage) == 0 {
		t.Errorf("[ERROR]: The Extended Key Usage extension is empty")
	}

	// Iterate over the OIDs in the ExtKeyUsage extension
	isExtendedKeyUsageValid := false
	var expectedKeyUsage asn1.ObjectIdentifier
	expectedKeyUsageName := ""
	if ca {
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
		t.Errorf("[ERROR]: Certificate has IsCA: %v  and does not contain specified key usage: %s", ca, expectedKeyUsageName)
	}
}

// Checks for KeyUsage Extension as per spec
// If IsCA = true, KeyUsage extension MUST contain DigitalSignature and KeyCertSign. BasicConstraints will also be checked that it matches the `IsCA` bool.
// If IsCA = false, KeyUsage extension MUST contain  only DigitalSignature
// If `label` is nil then the Ueid extension check is omitted.
func checkCertificateExtension(t *testing.T, extensions []pkix.Extension, label *[]byte, pubkey *client.DPEPubKey, isX509 bool, IssuerSki []byte, isCA bool, isCritical bool) {
	t.Helper()

	bc, err := getBasicConstraints(extensions)
	if err != nil {
		t.Error(err)
	}

	checkBasicConstraints(t, extensions, isCA)
	checkExtendedKeyUsages(t, extensions, bc.IsCA)
	if label != nil {
		checkTcgUeidExtension(t, extensions, *label, isCritical)
	}
	if isX509 {
		checkSubjectKeyIdentifierExtension(t, extensions, bc.IsCA, pubkey)
		checkKeyIdentifierExtension(t, extensions, bc.IsCA, IssuerSki)
	}

	// Check MultiTcbInfo Extension structure
	_, err = getMultiTcbInfo(extensions, isCritical)
	if err != nil {
		t.Error(err)
	}

	// Check for keyusage extension
	var allowedKeyUsages x509.KeyUsage

	if bc.IsCA {
		allowedKeyUsages = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	} else {
		allowedKeyUsages = x509.KeyUsageDigitalSignature
	}

	usage, err := getKeyUsage(extensions)
	if err != nil {
		t.Error(err)
	}

	certKeyUsageList := getKeyUsageNames(usage)
	allowedKeyUsageList := getKeyUsageNames(allowedKeyUsages)
	if usage != allowedKeyUsages {
		t.Errorf("[ERROR]: Certificate KeyUsage got %v but want %v ", certKeyUsageList, allowedKeyUsageList)
	}

}

// Validates SubjectKeyIdentifier in certificate returned by CertifyKey or DeriveContext commands
// against the isCa flag set in the BasicConstraints extension
// The SubjectKeyIdentifier extension MUST be included if isCA is true
// and MUST be excluded if isCA is false.
func checkSubjectKeyIdentifierExtension(t *testing.T, extensions []pkix.Extension, ca bool, pubkey *client.DPEPubKey) {
	t.Helper()

	ski, err := getSubjectKeyIdentifier(extensions)
	if err != nil {
		t.Errorf("[ERROR]: Failed to retrieve SubjectKeyIdentifier extension: %v", err)
	}
	if ca {
		if ski == nil {
			t.Errorf("[ERROR]: The certificate is a CA but the SubjectKeyIdentifier extension is not present.")
		}
		if pubkey == nil {
			return
		}
		var hasher hash.Hash
		if len(pubkey.X) == 32 {
			hasher = sha256.New()
			hasher.Write([]byte{0x04})
			hasher.Write(pubkey.X)
			hasher.Write(pubkey.Y)
		} else if len(pubkey.X) == 48 {
			hasher = sha512.New384()
			hasher.Write([]byte{0x04})
			hasher.Write(pubkey.X)
			hasher.Write(pubkey.Y)
		} else if len(pubkey.X) == 2592 {
			hasher = sha512.New384()
			hasher.Write(pubkey.X)
		} else {
			t.Errorf("[ERROR]: Unsupported public key length %d", len(pubkey.X))
			return
		}

		expectedKeyIdentifier := hasher.Sum(nil)[:20]
		if !reflect.DeepEqual(ski, expectedKeyIdentifier) {
			t.Errorf("[ERROR]: The value of the subject key identifier %v is not equal to the hash of the public key %v", ski, expectedKeyIdentifier)
		}
	} else if !ca && ski != nil {
		t.Errorf("[ERROR]: The certificate is not a CA but the SubjectKeyIdentifier extension is present.")
	}
}

// Validates AuthorityKeyIdentifier in certificate returned by CertifyKey or DeriveContext commands
// against the isCa flag set in the BasicConstraints extension
// The AuthorityKeyIdentifier extension MUST be included if isCA is true
// and MUST be excluded if isCA is false.
func checkKeyIdentifierExtension(t *testing.T, extensions []pkix.Extension, ca bool, IssuerSki []byte) {
	t.Helper()

	aki, err := getAuthorityKeyIdentifier(extensions)
	if err != nil {
		t.Errorf("[ERROR]: Failed to retrieve AuthorityKeyIdentifier extension: %v", err)
	}
	if aki.KeyIdentifier == nil {
		t.Fatal("[ERROR]: The certificate is a CA but the AuthorityKeyIdentifier extension is not present.")
	}
	if !reflect.DeepEqual(aki.KeyIdentifier, IssuerSki) {
		t.Errorf("[ERROR]: The value of the authority key identifier %v is not equal to the issuer's subject key identifier %v", aki, IssuerSki)
	}
}

// Validates basic constraints in certificate returned by CertifyKey or DeriveContext command
// against the flag set for input parameter.
// The BasicConstraints extension MUST be included
func checkBasicConstraints(t *testing.T, extensions []pkix.Extension, IsCA bool) {
	t.Helper()

	bc, err := getBasicConstraints(extensions)
	if err != nil {
		t.Error(err)
	}
	if bc.IsCA && !IsCA {
		t.Errorf("[ERROR]: basic constraint IsCA is set to %v but expected %v.", bc.IsCA, IsCA)
	}
}

// Parses X509 certificate
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
			// Certs in the Caliptra cert chain fail this lint currently.
			// We will need to truncate the serial numbers for those certs and
			// then enable this lint.
			"e_subject_dn_serial_number_max_length",
			// subject key identifiers are optional in leaf certificates.
			"w_ext_subject_key_identifier_missing_sub_cert",
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
		t.Fatalf("Certificate lint failed!")
	}
	return x509Cert
}

func testCertifyKey(d client.TestDPEInstance, c client.DPEClient, t *testing.T, simulation bool) {
	handle := getInitialContextHandle(d, c, t, simulation)
	defer func() {
		if simulation {
			c.DestroyContext(handle)
		}
	}()

	profile, err := client.GetTransportProfile(d)
	if err != nil {
		t.Fatalf("Could not get profile: %v", err)
	}
	digestLen := profile.GetDigestSize()

	seqLabel := make([]byte, digestLen)
	for i := range seqLabel {
		seqLabel[i] = byte(i)
	}

	certifyKeyParams := []CertifyKeyParams{
		{Label: make([]byte, digestLen), Flags: client.CertifyKeyFlags(0)},
		{Label: seqLabel, Flags: client.CertifyKeyFlags(0)},
	}

	for _, params := range certifyKeyParams {
		// Get DPE leaf certificate from CertifyKey
		certifyKeyResp, err := c.CertifyKey(handle, params.Label, client.CertifyKeyX509, params.Flags)
		if err != nil {
			t.Fatalf("[FATAL]: Could not certify key: %v", err)
		}

		// Get root and intermediate certificates to validate certificate chain of leaf cert
		certChainBytes, err := c.GetCertificateChain()
		if err != nil {
			t.Fatalf("[FATAL]: Could not get Certificate Chain: %v", err)
		}

		leafCertBytes := certifyKeyResp.Certificate

		// Run X.509 linter on full certificate chain and file issues for errors
		leafCert := checkCertificateStructure(t, leafCertBytes)
		certChain := checkCertificateChain(t, certChainBytes)

		// Check default context handle is unchanged
		checkCertifyKeyRespHandle(*certifyKeyResp, t, handle)

		// Check public key and algorithm parameters are correct
		checkPubKey(t, profile, leafCert.PublicKey, *certifyKeyResp)

		// Check all extensions
		isCritical := d.GetSupport().DpeInstanceMarkDiceExtensionsCritical
		checkCertificateExtension(t, leafCert.Extensions, &params.Label, &certifyKeyResp.Pub, true, certChain[len(certChain)-1].SubjectKeyId, false, isCritical)

		// Ensure full certificate chain has valid signatures
		// This also checks certificate lifetime, signatures as part of cert chain validation
		validateLeafCertChain(t, certChain, leafCert, profile)

		// Reassign handle for simulation mode.
		// However, this does not impact in default mode because
		// same default context handle is returned in default mode.
		handle = &certifyKeyResp.Handle
	}
	// TODO: When DeriveContext is implemented, call it here to add more TCIs and call CertifyKey again.
}

// Builds and verifies certificate chain.
func validateLeafCertChain(t *testing.T, certChain []*x509.Certificate, leafCert *x509.Certificate, profile client.Profile) {
	t.Helper()
	certsToProcess := []*x509.Certificate{leafCert}

	// Remove unhandled critical extensions and EKUs by x509 but defined in spec
	removeTcgDiceCriticalExtensions(t, certsToProcess)
	removeTcgDiceExtendedKeyUsages(t, certsToProcess)

	if profile == client.ProfileMldsa87 {
		// Manual verification for ML-DSA
		if len(certChain) == 0 {
			t.Errorf("[ERROR]: Certificate chain is empty")
			return
		}
		issuer := certChain[len(certChain)-1]

		var spki struct {
			Algorithm        pkix.AlgorithmIdentifier
			SubjectPublicKey asn1.BitString
		}
		if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &spki); err != nil {
			t.Errorf("[ERROR]: Failed to parse issuer SPKI: %v", err)
			return
		}

		var pk mldsa87.PublicKey
		if err := pk.UnmarshalBinary(spki.SubjectPublicKey.Bytes); err != nil {
			t.Errorf("[ERROR]: Failed to parse issuer ML-DSA public key: %v", err)
			return
		}

		if !mldsa87.Verify(&pk, leafCert.RawTBSCertificate, nil, leafCert.Signature) {
			t.Error("[ERROR]: ML-DSA Leaf Certificate Signature Verification failed")
		} else {
			t.Log("ML-DSA Leaf Certificate Signature Verified manually")
		}
		return
	}

	// Certificate chain validation for leaf
	opts := buildVerifyOptions(t, certChain)
	chains, err := leafCert.Verify(opts)
	if err != nil {
		t.Errorf("[ERROR]: Error verifying DPE leaf: %s", err.Error())
	}

	// Log certificate chains linked to leaf
	if len(chains) != 1 {
		t.Errorf("[ERROR]: Unexpected number of cert chains: %d", len(chains))
	}
}

// Builds Certificate chain verifier parameters.
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

// Gets KeyUsage bitmap and returns as list of KeyUsage name strings.
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

func checkPubKey(t *testing.T, p client.Profile, pubkey any, response client.CertifiedKey) {
	if p == client.ProfileMldsa87 {
		// TODO(clundin): Check ML-DSA Pub key.
		return
	}

	var pubKeyInResponse ecdsa.PublicKey
	switch p {
	case client.ProfileMinP256SHA256:
		fallthrough
	case client.ProfileP256SHA256:
		pubKeyInResponse = ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(response.Pub.X),
			Y:     new(big.Int).SetBytes(response.Pub.Y),
		}
	case client.ProfileMinP384SHA384:
		fallthrough
	case client.ProfileP384SHA384:
		pubKeyInResponse = ecdsa.PublicKey{
			Curve: elliptic.P384(),
			X:     new(big.Int).SetBytes(response.Pub.X),
			Y:     new(big.Int).SetBytes(response.Pub.Y),
		}
	default:
		t.Errorf("[ERROR]: Unsupported profile %v", p)
	}

	ecdsaPub, ok := pubkey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("[FATAL]: Public key is not a ecdsa key")
	}

	if !(pubKeyInResponse.Equal(ecdsaPub)) {
		t.Errorf("[ERROR]: Public key returned in response must match the Public Key Info in the certificate.")
	}
}

// Checks whether the context handle is unchanged after certifyKey command when default context handle is used.
func checkCertifyKeyRespHandle(res client.CertifiedKey, t *testing.T, handle *client.ContextHandle) {
	if *handle != client.DefaultContextHandle {
		t.Logf("[LOG]: Handle is not default context, skipping check...")
		return
	}

	if res.Handle != *handle {
		t.Errorf("[ERROR]: Handle must be unchanged by CertifyKey, want original handle %v but got %v", handle, res.Handle)
	}
}
