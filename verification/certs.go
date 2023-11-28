// Licensed under the Apache-2.0 license

package verification

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"reflect"
	"time"

	"golang.org/x/exp/slices"
)

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
	OidSHA256                          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OidSHA384                          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
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

// A tcg-dice-MultiTcbInfo extension.
// This extension SHOULD be marked as critical.
func getMultiTcbInfo(c *x509.Certificate) (TcgMultiTcbInfo, error) {
	var multiTcbInfo TcgMultiTcbInfo

	// Check MultiTcbInfo Extension
	//tcg-dice-MultiTcbInfo extension
	for _, ext := range c.Extensions {
		if ext.Id.Equal(OidExtensionTcgDiceMultiTcbInfo) { // OID for Tcg Dice MultiTcbInfo
			if !ext.Critical {
				return multiTcbInfo, fmt.Errorf("multiTcbInfo extension is not marked as CRITICAL")
			}
			_, err := asn1.Unmarshal(ext.Value, &multiTcbInfo)
			if err != nil {
				// multiTcb info is not provided in leaf
				return multiTcbInfo, fmt.Errorf("failed to unmarshal MultiTcbInfo field: %v", err)
			}
			break
		}
	}
	return multiTcbInfo, nil
}

func getTcbInfoForHandle(c DPEClient, handle *ContextHandle) (*ContextHandle, DiceTcbInfo, error) {
	outHandle := handle

	// Get digest size
	profile, err := c.GetProfile()
	if err != nil {
		return outHandle, DiceTcbInfo{}, fmt.Errorf("cannot get profile: %s", err)
	}

	digestLen := profile.Profile.GetDigestSize()
	label := make([]byte, digestLen)

	certifiedKey, err := c.CertifyKey(outHandle, label, CertifyKeyX509, 0)
	if err != nil {
		return outHandle, DiceTcbInfo{}, fmt.Errorf("could not certify key: %s", err)
	}

	outHandle = &certifiedKey.Handle
	leafCertBytes := certifiedKey.Certificate

	var leafCert *x509.Certificate

	// Check whether certificate is DER encoded.
	if leafCert, err = x509.ParseCertificate(leafCertBytes); err != nil {
		return outHandle, DiceTcbInfo{}, err
	}

	// Get DICE information from MultiTcbInfo Extension
	multiTcbInfo, err := getMultiTcbInfo(leafCert)
	if err != nil {
		return outHandle, DiceTcbInfo{}, err
	}

	if len(multiTcbInfo) == 0 {
		return outHandle, DiceTcbInfo{}, fmt.Errorf("certificate MutliTcbInfo is empty")
	}

	return outHandle, multiTcbInfo[0], nil
}

// Removes the critical extensions that are unknown to x509 package
// but defined in DPE certificate profile specification for cert chain validation
// UnhandledCriticalExtensions may have only custom extensions mentioned in spec
// unknownExtnMap collects extensions unknown to both x509 and the DICE certificate profiles spec
// positive case expects the unknownExtnMap to be empty.
func removeTcgDiceCriticalExtensions(certs []*x509.Certificate) error {
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
	msg := ""
	if len(unknownExtnMap) > 0 {
		for certSubject, ext := range unknownExtnMap {
			msg += fmt.Errorf("certificate \"%s\" has unhandled critical extension \"%s\"", certSubject, ext).Error()
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}

// Ignores extended key usages that are unknown to x509 package
// but atleast defined in DPE certificate profile specification for cert chain validation
// UnhandledExtendedKeyUsages may have only custom key usages mentioned in spec
// unknownKeyUsagesMap collects keyusages unknown to both x509 and the DICE certificate profiles spec
// positive case expects the unknownKeyUsagesMap to be empty.
func removeTcgDiceExtendedKeyUsages(certs []*x509.Certificate) error {
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
	msg := ""
	if len(unknownKeyUsagesMap) > 0 {
		for certSubject, ext := range unknownKeyUsagesMap {
			msg += fmt.Errorf("certificate \"%s\" has unhandled critical extension \"%s\"", certSubject, ext).Error()
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}

// A tcg-dice-Ueid extension MUST be added
// UEID extension be populated by the LABEL input parameter to CertifyKey command
// The extension SHOULD be marked as critical
func checkTcgUeidExtension(c *x509.Certificate, label []byte) error {
	isFound := false
	// Check UEID extension
	for _, ext := range c.Extensions {
		if ext.Id.Equal(OidExtensionTcgDiceUeid) {
			isFound = true
			if !ext.Critical {
				return fmt.Errorf("tcg-dice-Ueid extension is NOT marked as CRITICAL")
			}
			var ueid TcgUeidExtension = TcgUeidExtension{}
			_, err := asn1.Unmarshal(ext.Value, &ueid)
			if err != nil {
				return fmt.Errorf("unable to unmarshal value of UEID extension, %s", err.Error())
			}

			if !reflect.DeepEqual(ueid.Ueid, label) {
				// Ueid extn value doen not match the label
				return fmt.Errorf("tcg-dice-Ueid value does not match with the \"Label\" of certified key")
			}
			break
		}
	}
	if !isFound {
		return fmt.Errorf("tcg-dice-Ueid extension is missing")
	}
	return nil
}

// Checks whether the VendorInfo is 4-bytes TARGET_LOCALITY parameter
func checkDiceTcbVendorInfo(currentTcbInfo DiceTcbInfo, targetLocality uint32) error {
	var err error
	expectedVendorInfo := make([]byte, 4)
	binary.BigEndian.PutUint32(expectedVendorInfo, targetLocality)
	if !bytes.Equal(currentTcbInfo.VendorInfo, expectedVendorInfo) {
		err = fmt.Errorf("unexpected VendorInfo for current DICE TCB block, want %v but got %v", expectedVendorInfo, currentTcbInfo.VendorInfo)
	}
	return err
}

// Checks whether INPUT_TYPE passed to a deriveChild Request
// populates the "type" field in the DiceTcbInfo extension.
func checkCurrentDiceTcbTciType(currentTcbInfo DiceTcbInfo, expectedTciType uint32) error {
	var err error
	expectedTciTypeBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(expectedTciTypeBytes, expectedTciType)
	if !bytes.Equal(currentTcbInfo.Type, expectedTciTypeBytes) {
		err = fmt.Errorf("unexpected TCI type for current DICE TCB block, want %v but got %v", expectedTciTypeBytes, currentTcbInfo.Type)
	}
	return err
}

// Checks whether the Hash Algorithm field in FWID block is correct
func checkDiceTcbHashAlgorithm(currentTcbInfo DiceTcbInfo, hashAlg asn1.ObjectIdentifier) error {
	for _, fwid := range currentTcbInfo.Fwids {
		if !fwid.HashAlg.Equal(hashAlg) {
			return fmt.Errorf("unexpected hash algorithm in FWID block, expected %s but got %s", hashAlg, fwid.HashAlg)
		}
	}
	return nil
}

// Checks whether certificate extended key usage is as per spec
// OID for ExtendedKeyUsage Extension: 2.5.29.37
// The ExtendedKeyUsage extension SHOULD be marked as critical
// If IsCA = true, the extension SHOULD contain tcg-dice-kp-eca
// If IsCA = false, the extension SHOULD contain tcg-dice-kp-attestLoc
func checkExtendedKeyUsages(c *x509.Certificate) error {
	extKeyUsage := []asn1.ObjectIdentifier{}

	for _, ext := range c.Extensions {
		if ext.Id.Equal(OidExtensionExtKeyUsage) { // OID for ExtKeyUsage extension
			// Extract the OID value from the extension
			_, err := asn1.Unmarshal(ext.Value, &extKeyUsage)
			if err != nil {
				return fmt.Errorf("unable to unmarshal the Extended Key Usage extension: %v", err)
			}

			if !ext.Critical {
				return fmt.Errorf("extended key usage is not marked critical")
			}
			break
		}
	}

	if len(extKeyUsage) == 0 {
		return fmt.Errorf("extended key usage is empty")
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
		return fmt.Errorf("certificate has IsCA: %v  and does not contain specified key usage: %s", c.IsCA, expectedKeyUsageName)
	}
	return nil
}

// Checks for KeyUsage Extension as per spec
// If IsCA = true, KeyUsage extension MUST contain DigitalSignature and KeyCertSign
// If IsCA = false, KeyUsage extension MUST contain  only DigitalSignature
func checkKeyExtensions(c *x509.Certificate) error {
	var allowedKeyUsages x509.KeyUsage
	var err error

	if c.IsCA {
		allowedKeyUsages = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	} else {
		allowedKeyUsages = x509.KeyUsageDigitalSignature
	}

	certKeyUsageList := getKeyUsageNames(c.KeyUsage)
	allowedKeyUsageList := getKeyUsageNames(allowedKeyUsages)
	if c.KeyUsage != allowedKeyUsages {
		err = fmt.Errorf("certificate has IsCA: %v and has got %v but want %v", c.IsCA, certKeyUsageList, allowedKeyUsageList)
	}
	return err

}

// Validates basic constraints in certificate against the input flag passed to CertifyKey command
// BasicConstraints extension MUST be included
// If CertifyKey AddIsCA is set, IsCA MUST be set to true.
// If CertifyKey AddIsCA is NOT set, IsCA MUST be set to false
func checkBasicConstraints(c *x509.Certificate, flags CertifyKeyFlags) error {
	var err error
	flagsBuf := &bytes.Buffer{}
	binary.Write(flagsBuf, binary.LittleEndian, flags)

	flagIsCA := CertifyAddIsCA&flags != 0
	if flagIsCA != c.IsCA {
		err = fmt.Errorf("basic constraint IsCA must be %v, got %v", flagIsCA, c.IsCA)
	}
	return err
}

// Builds and verifies certificate chain.
func validateLeafCertChain(certChain []*x509.Certificate, leafCert *x509.Certificate) error {
	var err error
	certsToProcess := []*x509.Certificate{leafCert}

	// Remove unhandled critical extensions reported by x509 but defined in spec
	if err = removeTcgDiceCriticalExtensions(certsToProcess); err != nil {
		return err
	}

	// Remove unhandled extended key usages reported by x509 but defined in spec
	if err = removeTcgDiceExtendedKeyUsages(certsToProcess); err != nil {
		return err
	}

	// Build verify options
	var opts *x509.VerifyOptions
	if opts, err = buildVerifyOptions(certChain); err != nil {
		return err
	}

	// Certificate chain validation for leaf
	chains, err := leafCert.Verify(*opts)
	if err != nil {
		// Unable to build certificate chain from leaf to root
		return fmt.Errorf("error verifying DPE leaf: %s", err.Error())
	}

	// Log certificate chains linked to leaf
	if len(chains) != 1 {
		return fmt.Errorf("unexpected number of cert chains: %d", len(chains))
	}
	return nil
}

// Builds Certificate chain verifier parameters.
func buildVerifyOptions(certChain []*x509.Certificate) (*x509.VerifyOptions, error) {
	var err error
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()

	// Root certificate is expected to be in the beginning of the chain, the rest are expected to be intermediates.
	roots.AddCert(certChain[0])

	for _, cert := range certChain[1:] {
		if cert.Subject.String() == cert.Issuer.String() {
			return nil, fmt.Errorf("found a self-signed certificate in middle of certificate chain returned by GetCertificateChain")
		}
		intermediates.AddCert(cert)
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now().UTC(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	return &opts, err
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

// Verifies the TCI_Current and TCI_Cumulative of dice tcb information blocks
func verifyDiceTcbDigest(tcbInfo DiceTcbInfo, wantCurrentTCI []byte, lastCumulativeTCI []byte) error {
	var err error

	// Check TCI_CURRENT
	currentTCI := tcbInfo.Fwids[0].Digest
	if !bytes.Equal(currentTCI, wantCurrentTCI) {
		err = fmt.Errorf("unexpected TCI_CURRENT digest, want %v but got %v", wantCurrentTCI, currentTCI)
	}

	// Check TCI_CUMULATIVE against expected cumulative TCI
	wantCumulativeTCI := computeExpectedCumulative(lastCumulativeTCI, currentTCI)
	cumulativeTCI := tcbInfo.Fwids[1].Digest
	if !bytes.Equal(cumulativeTCI, wantCumulativeTCI) {
		err = fmt.Errorf("unexpected TCI_CUMULATIVE value, want %v but got %v", wantCumulativeTCI, cumulativeTCI)
	}
	return err
}

// Checks the FWID block's Digest.
// FWID at index 0 has the TCI_CURRENT as digest
// FWID at index 1 has the TCI_CUMULATIVE as digest
// FWID array always has two digest/hashAlg blocks when "ExtendTci" is supported by DPE profile.
func validateDiceTcbFwids(leafCertBytes []byte, currentTcis [][]byte, digestLen int) error {
	var leafCert *x509.Certificate
	var err error

	// Check whether certificate is DER encoded.
	if leafCert, err = x509.ParseCertificate(leafCertBytes); err != nil {
		return err
	}

	// Get DICE information from MultiTcbInfo Extension
	var multiTcbInfo []DiceTcbInfo
	if multiTcbInfo, err = getMultiTcbInfo(leafCert); err != nil {
		return err
	}

	if len(multiTcbInfo) == 0 {
		return fmt.Errorf("certificate MutliTcbInfo is empty")
	}

	// Calculate expected cumulative value
	defaultTci := make([]byte, digestLen)

	// Check cumulative, current TCI at the last index of  multitcb info
	// It must have default TCI value
	lastIndex := len(multiTcbInfo) - 1
	if !bytes.Equal(multiTcbInfo[lastIndex].Fwids[0].Digest, defaultTci) {
		return fmt.Errorf("current TCI value for first TCB block, want %v but got %v", defaultTci, multiTcbInfo[lastIndex].Fwids[0].Digest)
	}

	if !bytes.Equal(multiTcbInfo[lastIndex].Fwids[1].Digest, defaultTci) {
		return fmt.Errorf("cumulative TCI value for first TCB block, want %v but got %v", defaultTci, multiTcbInfo[lastIndex].Fwids[1].Digest)
	}

	// Check cumulative, current TCI of other indices if any
	lastCumulativeTCI := defaultTci
	multiTcbInfo = multiTcbInfo[:lastIndex]

	for i, tcbinfo := range multiTcbInfo {
		wantCurrentTci := currentTcis[i]
		verifyDiceTcbDigest(tcbinfo, wantCurrentTci, lastCumulativeTCI)
	}
	return err
}
