// Licensed under the Apache-2.0 license

package verification

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"reflect"
	"testing"

	"go.mozilla.org/pkcs7"

	zx509 "github.com/zmap/zcrypto/x509"
	zlint "github.com/zmap/zlint/v3"
	"github.com/zmap/zlint/v3/lint"
)

type CertifyKeyParams struct {
	Label []byte
	Flags CertifyKeyFlags
}

func TestCertifyKey(d TestDPEInstance, c DPEClient, t *testing.T) {
	testCertifyKey(d, c, t, false)
}

func TestCertifyKeySimulation(d TestDPEInstance, c DPEClient, t *testing.T) {
	testCertifyKey(d, c, t, true)
}

// Checks whether FWID array omits index-1 when extend TCI is not supported in DPE profile.
func TestCertifyKeyWithoutExtendTciSupport(d TestDPEInstance, c DPEClient, t *testing.T) {
	simulation := false
	handle := getInitialContextHandle(d, c, t, simulation)

	profile, err := GetTransportProfile(d)
	if err != nil {
		t.Fatalf("Could not get profile: %v", err)
	}
	digestLen := profile.GetDigestSize()

	// Get DPE leaf certificate from CertifyKey
	certifiedKey, err := c.CertifyKey(handle, make([]byte, digestLen), CertifyKeyX509, CertifyKeyFlags(0))
	if err != nil {
		t.Fatalf("[FATAL]: Could not certify key: %v", err)
	}

	leafCertBytes := certifiedKey.Certificate
	var leafCert *x509.Certificate

	if leafCert, err = x509.ParseCertificate(leafCertBytes); err != nil {
		t.Errorf("[ERROR]: Could not parse leaf certificate %s", err)
	}

	multiTcbInfo, err := getMultiTcbInfo(leafCert.Extensions)
	if err != nil {
		t.Errorf("[ERROR]: Could not parse multi TCB information: extension %s", err)
	}

	if len(multiTcbInfo) == 0 {
		t.Errorf("[ERROR]: Certificate MutliTcbInfo is empty")
	}

	// Check whether fwids array has only fwids[0] i.e, TCI_CURRENT measurement
	// and TCI_CUMULATIVE i.e fwids[1] is omitted in every Dice TCB info block
	for i, tcbinfo := range multiTcbInfo {
		if len(tcbinfo.Fwids) != 1 {
			t.Errorf("Extend TCI is not supported by profile, expected FWIDs length in block-%d is %d but got %d", i, 1, len(tcbinfo.Fwids))
		}
	}
}

func TestCertifyKey_Csr(d TestDPEInstance, c DPEClient, t *testing.T) {
	ctx := getInitialContextHandle(d, c, t, false)

	profile, err := GetTransportProfile(d)
	if err != nil {
		t.Fatalf("Could not get profile: %v", err)
	}
	digestLen := profile.GetDigestSize()

	flags := CertifyKeyFlags(0)
	label := make([]byte, digestLen)

	// Get DPE leaf certificate from CertifyKey
	certifyKeyResp, err := c.CertifyKey(ctx, label, CertifyKeyCsr, flags)
	if err != nil {
		t.Fatalf("[FATAL]: Could not certify key: %v", err)
	}

	wrappedCSR, err := pkcs7.Parse(certifyKeyResp.Certificate)
	if err != nil {
		t.Fatalf("[FATAL]: Could not unmarshal CSR CMS message: %v", err)
	}

	// Check signature on the CMS message
	certChainBytes, err := c.GetCertificateChain()
	if err != nil {
		t.Fatalf("[FATAL]: Could not get Certificate Chain: %v", err)
	}
	certChain := checkCertificateChain(t, certChainBytes)
	lastCertInCertChain := certChain[len(certChain)-1]

	// Get DPE leaf cert
	certifyKeyResp, err = c.CertifyKey(ctx, label, CertifyKeyX509, flags)
	if err != nil {
		t.Fatalf("[FATAL]: Could not certify key: %v", err)
	}
	leafCert := checkCertificateStructure(t, certifyKeyResp.Certificate)

	// This library expects the issuer of the cert to match the issuer of the CMS.
	//
	// The last cert in the cert chain would be signed by the preceding cert
	// so its issuer is not what the library expects. The DPE leaf cert is signed
	// by the alias key so it's issuer will match the issuer of the CMS.
	lastCertInCertChain.RawIssuer = leafCert.RawIssuer

	// This library expects the cert to be in the Certificates field but DPE
	// does not populate it. Add it so Verify succeeds.
	//
	// It is still compliant that DPE does not produce the certificate chain.
	// From PKCS#7 section 9.1:
	//		There may also be fewer certificates than necessary, if it is expected that
	//		those verifying the signatures have an alternate means of
	//		obtaining necessary certificates (e.g., from a previous set
	//      of certificates).
	wrappedCSR.Certificates = append(wrappedCSR.Certificates, lastCertInCertChain)
	err = wrappedCSR.Verify()
	if err != nil {
		t.Errorf("[ERROR]: Failed to verify CMS wrapper signature: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(wrappedCSR.Content)
	if err != nil {
		t.Fatalf("[FATAL]: Could not parse CSR: %v", err)
	}

	// Check fields and extensions in the CSR
	checkCertifyKeyExtensions(t, csr.Extensions, flags, label)
	checkPubKey(t, profile, csr.PublicKey, *certifyKeyResp)

	// Check that CSR is self-signed
	err = csr.CheckSignature()
	if err != nil {
		t.Errorf("[ERROR] CSR is not self-signed: %v", err)
	}
}

func testCertifyKey(d TestDPEInstance, c DPEClient, t *testing.T, simulation bool) {
	handle := getInitialContextHandle(d, c, t, simulation)
	if simulation {
		// Clean up contexts
		defer func() {
			err := c.DestroyContext(handle, DestroyDescendants)
			if err != nil {
				t.Errorf("[ERROR]: Error while cleaning contexts, this may cause failure in subsequent tests: %s", err)
			}
		}()
	}

	profile, err := GetTransportProfile(d)
	if err != nil {
		t.Fatalf("Could not get profile: %v", err)
	}
	digestLen := profile.GetDigestSize()
	seqLabel := make([]byte, digestLen)
	for i := range seqLabel {
		seqLabel[i] = byte(i)
	}

	certifyKeyParams := []CertifyKeyParams{
		{Label: make([]byte, digestLen), Flags: CertifyKeyFlags(0)},
		{Label: make([]byte, digestLen), Flags: CertifyKeyFlags(CertifyAddIsCA)},
		{Label: seqLabel, Flags: CertifyKeyFlags(0)},
	}

	for _, params := range certifyKeyParams {
		// Get DPE leaf certificate from CertifyKey
		certifyKeyResp, err := c.CertifyKey(handle, params.Label, CertifyKeyX509, params.Flags)
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
		checkCertifyKeyExtensions(t, leafCert.Extensions, params.Flags, params.Label)

		// Ensure full certificate chain has valid signatures
		// This also checks certificate lifetime, signatures as part of cert chain validation
		if err = validateLeafCertChain(certChain, leafCert); err != nil {
			t.Errorf("[ERROR]: %v", err)
		}

		// Reassign handle for simulation mode.
		// However, this does not impact in default mode because
		// same default context handle is returned in default mode.
		handle = &certifyKeyResp.Handle
	}
	// DeriveChild to add more TCIs and call CertifyKey again.
	if simulation {
		handle = checkWithDerivedChildContextSimulation(d, c, t, handle)
	} else {
		checkWithDerivedChildContext(d, c, t, handle)
	}
}

// Checks Multi Tcb Info for context derived from non-simulation mode
// Check CertifyKey command after adding more TCIs by DeriveChild command.
// The MultiTcbInfo extension has a DiceTcbInfo block for each TCI node.
// In a DiceTcbInfo block of a given TCI node,
//   - the "type" field must contain 4-byte tciType is provided by a client to DeriveChild.
//   - the "fwid" field must contain cumulative TCI measurement.
func checkWithDerivedChildContext(d TestDPEInstance, c DPEClient, t *testing.T, handle *ContextHandle) {
	profile, err := GetTransportProfile(d)
	if err != nil {
		t.Fatalf("Could not get profile: %v", err)
	}
	digestLen := profile.GetDigestSize()

	var hashAlg asn1.ObjectIdentifier
	if digestLen == 32 {
		hashAlg = OidSHA256
	} else if digestLen == 48 {
		hashAlg = OidSHA384
	}

	childTCI1 := make([]byte, digestLen)
	for i := range childTCI1 {
		childTCI1[i] = byte(i + 1)
	}

	// Set tciType to verify in multiTcbInfo extension
	tciType := uint32(2)

	// Preserve parent context to restore for subsequent tests
	parentHandle, err := c.RotateContextHandle(handle, RotateContextHandleFlags(0))
	if err != nil {
		t.Errorf("[ERROR]: Error while rotating parent context handle, this may cause failure in subsequent tests: %s", err)
	}

	// Deferred call to restore default context handle for subsequent tests
	defer func() {
		_, err = c.RotateContextHandle(parentHandle, RotateContextHandleFlags(TargetIsDefault))
		if err != nil {
			t.Errorf("[ERROR]: Error while restoring parent context handle as default context handle, this may cause failure in subsequent tests: %s", err)
		}
	}()

	// Derive Child context with input data, tag it and check TCI_CUMULATIVE
	childCtx, err := c.DeriveChild(parentHandle,
		childTCI1,
		DeriveChildFlags(InputAllowX509|RetainParent),
		tciType,
		0)

	if err != nil {
		t.Fatalf("[FATAL]: Error while creating child handle: %s", err)
	}

	childHandle := &childCtx.NewContextHandle
	parentHandle = &childCtx.ParentContextHandle

	// Clean up contexts
	defer func() {
		err := c.DestroyContext(childHandle, DestroyDescendants)
		if err != nil {
			t.Errorf("[ERROR]: Error while cleaning up derived context, this may cause failure in subsequent tests: %s", err)
		}
	}()

	var childTcbInfo DiceTcbInfo
	childHandle, childTcbInfo, err = getTcbInfoForHandle(c, childHandle)
	if err != nil {
		t.Fatalf("[FATAL]: Could not get TcbInfo: %v", err)
	}

	// Check vendorInfo field in multitcb
	if err = checkDiceTcbVendorInfo(childTcbInfo, d.GetLocality()); err != nil {
		t.Errorf("[ERROR]: %v", err)
	}

	// Check tci type field in multitcb
	if err = checkCurrentDiceTcbTciType(childTcbInfo, tciType); err != nil {
		t.Errorf("[ERROR]: %v", err)
	}

	// Check hash algorithm field in multitcb
	if err = checkDiceTcbHashAlgorithm(childTcbInfo, hashAlg); err != nil {
		t.Errorf("[ERROR]: %v", err)
	}

	// Extend TCI support is mandatory for this validation
	if !d.GetSupport().ExtendTci {
		t.Errorf("ExtendTCI is unsupported by profile, unable to run tests to verify TCI_CUMULATIVE measurement")
		return
	}

	// Check dice tcb measurements of derived children
	// Add one more child context
	childTCI2 := make([]byte, digestLen)
	for i := range childTCI2 {
		childTCI2[i] = byte(i + 2)
	}

	childCtx, err = c.DeriveChild(childHandle,
		childTCI2,
		DeriveChildFlags(InputAllowX509),
		tciType,
		0)

	if err != nil {
		t.Fatalf("[FATAL]: Error while creating child handle: %s", err)
	}

	childHandle = &childCtx.NewContextHandle

	// Get latest TCB information
	certifiedKey, err := c.CertifyKey(childHandle, childTCI2, CertifyKeyX509, 0)
	if err != nil {
		t.Fatalf("[FATAL]: Could not certify key: %s", err)
	}

	childHandle = &certifiedKey.Handle
	leafCertBytes := certifiedKey.Certificate

	// Build list of tci_current for validation and use it for validating TCI measurements
	currentTCIs := [][]byte{childTCI2, childTCI1}
	if err = validateDiceTcbFwids(leafCertBytes, currentTCIs, digestLen); err != nil {
		t.Errorf("[ERROR]: %v", err)
	}
}

// Checks Multi Tcb Info for context derived from simulation mode
func checkWithDerivedChildContextSimulation(d TestDPEInstance, c DPEClient, t *testing.T, handle *ContextHandle) *ContextHandle {
	profile, err := GetTransportProfile(d)
	if err != nil {
		t.Fatalf("Could not get profile: %v", err)
	}
	digestLen := profile.GetDigestSize()

	var hashAlg asn1.ObjectIdentifier
	if digestLen == 32 {
		hashAlg = OidSHA256
	} else if digestLen == 48 {
		hashAlg = OidSHA384
	}

	childTCI := make([]byte, digestLen)
	for i := range childTCI {
		childTCI[i] = byte(i)
	}

	// Set tciType to verify in UEID extension
	tciType := uint32(2)

	locality := d.GetLocality()

	// Derive Child context with input data, tag it and check TCI_CUMULATIVE
	childCtx, err := c.DeriveChild(handle,
		childTCI,
		DeriveChildFlags(InputAllowX509|ChangeLocality|RetainParent),
		tciType,
		locality+1) // Switch locality to derive child context from Simulation context

	if err != nil {
		t.Fatalf("[FATAL]: Error while creating child handle: %s", err)
	}

	handle = &childCtx.NewContextHandle
	parentHandle := &childCtx.ParentContextHandle

	// Clean up contexts
	defer func() {
		err := c.DestroyContext(handle, DestroyDescendants)
		if err != nil {
			t.Errorf("[ERROR]: Error while cleaning up derived context, this may cause failure in subsequent tests: %s", err)
		}
		// Revert locality for other tests
		d.SetLocality(0)
	}()

	// Switch to simulated child context locality to issue CertifyKey command
	d.SetLocality(locality + 1)

	// Make CertifyKey call and get current MultiTcbInfo
	var leafCert *x509.Certificate

	certifiedKey, err := c.CertifyKey(handle, childTCI, CertifyKeyX509, 0)
	if err != nil {
		t.Errorf("[ERROR]: Could not certify key: %s", err)
	}

	handle = &certifiedKey.Handle // Update handle
	leafCertBytes := certifiedKey.Certificate

	if leafCert, err = x509.ParseCertificate(leafCertBytes); err != nil {
		t.Errorf("[ERROR]: Could not parse certificate: %s", err)
	}

	multiTcbInfo, err := getMultiTcbInfo(leafCert.Extensions)
	if err != nil {
		t.Errorf("[ERROR]: Could not parse multi TCB info extension: %s", err)
	}

	if len(multiTcbInfo) == 0 {
		t.Errorf("[ERROR]: Certificate MutliTcbInfo is empty")
	}

	childTcbInfo := multiTcbInfo[0]
	if !bytes.Equal(childTcbInfo.Fwids[0].Digest, childTCI) {
		t.Errorf("[ERROR]: Got current TCI %x, expected %x", childTcbInfo.Fwids[0].Digest, childTCI)
	}

	// Preform checks on multi Tcb info of child TCI node
	// Check vendorInfo field
	if err = checkDiceTcbVendorInfo(childTcbInfo, d.GetLocality()); err != nil {
		t.Errorf("[ERROR]: %v", err)
	}

	// Check type field
	if err = checkCurrentDiceTcbTciType(childTcbInfo, tciType); err != nil {
		t.Errorf("[ERROR]: %v", err)
	}

	// Check hash algorithm
	if err = checkDiceTcbHashAlgorithm(childTcbInfo, hashAlg); err != nil {
		t.Errorf("[ERROR]: %v", err)
	}

	// Extend TCI support is mandatory for this validation
	if !d.GetSupport().ExtendTci {
		t.Errorf("ExtendTCI is unsupported by profile, unable to run tests to verify TCI_CUMULATIVE measurements")
		return parentHandle
	}

	// Check all dice tcb measurements
	// Build list of tci_current for validation
	currentTCIs := [][]byte{childTCI}
	if err = validateDiceTcbFwids(certifiedKey.Certificate, currentTCIs, digestLen); err != nil {
		t.Errorf("[ERROR]: %v", err)
	}
	return parentHandle
}

func checkPubKey(t *testing.T, p Profile, pubkey any, response CertifiedKey) {
	var pubKeyInResponse ecdsa.PublicKey
	switch p {
	case ProfileP256SHA256:
		pubKeyInResponse = ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(response.Pub.X),
			Y:     new(big.Int).SetBytes(response.Pub.Y),
		}
	case ProfileP384SHA384:
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
func checkCertifyKeyRespHandle(res CertifiedKey, t *testing.T, handle *ContextHandle) {
	if *handle != DefaultContextHandle {
		t.Logf("[LOG]: Handle is not default context, skipping check...")
		return
	}

	if res.Handle != *handle {
		t.Errorf("[ERROR]: Handle must be unchanged by CertifyKey, want original handle %v but got %v", handle, res.Handle)
	}
}

// Parses X509 certificate
func checkCertificateStructure(t *testing.T, certBytes []byte) *x509.Certificate {
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

// A tcg-dice-Ueid extension MUST be added
// This SHALL be populated by the LABEL input parameter to CertifyKey
// The extension SHOULD be marked as critical
func checkCertifyKeyTcgUeidExtension(t *testing.T, extensions []pkix.Extension, label []byte) {
	t.Helper()

	ueid, err := getUeid(extensions)
	if err != nil {
		t.Errorf("[ERROR]: tcg-dice-Ueid extension is missing: %v", err)
	}

	if !reflect.DeepEqual(ueid.Ueid, label) {
		// Ueid extn value doen not match the label
		t.Errorf("[ERROR]: tcg-dice-Ueid value does not match with the \"Label\" passed in CertifyKeyRequest")
	}
}

// Checks whether certificate extended key usage is as per spec
// OID for ExtendedKeyUsage Extension: 2.5.29.37
// The ExtendedKeyUsage extension SHOULD be marked as critical
// If IsCA = true, the extension SHOULD contain tcg-dice-kp-eca
// If IsCA = false, the extension SHOULD contain tcg-dice-kp-attestLoc
func checkCertifyKeyExtendedKeyUsages(t *testing.T, extensions []pkix.Extension, ca bool) {
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

// // Checks for KeyUsage Extension as per spec
// // If IsCA = true, KeyUsage extension MUST contain DigitalSignature and KeyCertSign
// // If IsCA = false, KeyUsage extension MUST contain  only DigitalSignature
func checkCertifyKeyExtensions(t *testing.T, extensions []pkix.Extension, flags CertifyKeyFlags, label []byte) {
	t.Helper()

	bc, err := getBasicConstraints(extensions)
	if err != nil {
		t.Error(err)
	}

	checkCertifyKeyBasicConstraints(t, extensions, flags)
	checkCertifyKeyExtendedKeyUsages(t, extensions, bc.IsCA)
	checkCertifyKeyTcgUeidExtension(t, extensions, label)

	// Check MultiTcbInfo Extension structure
	_, err = getMultiTcbInfo(extensions)
	if err != nil {
		t.Error(err)
	}

	//Check for keyusage extension
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

// Validates basic constraints in certificate returned by CertifyKey command
// against the flag set for input parameter.
// The BasicConstraints extension MUST be included
// If CertifyKey AddIsCA is set, IsCA MUST be set to true.
// If CertifyKey AddIsCA is NOT set, IsCA MUST be set to false
func checkCertifyKeyBasicConstraints(t *testing.T, extensions []pkix.Extension, flags CertifyKeyFlags) {
	t.Helper()

	flagsBuf := &bytes.Buffer{}
	binary.Write(flagsBuf, binary.LittleEndian, flags)

	bc, err := getBasicConstraints(extensions)
	if err != nil {
		t.Error(err)
	}

	flagIsCA := CertifyAddIsCA&flags != 0
	if flagIsCA != bc.IsCA {
		t.Errorf("[ERROR]: ADD_IS_CA is set to %v but the basic constraint IsCA is set to %v", flagIsCA, bc.IsCA)
	}
}