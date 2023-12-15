// Licensed under the Apache-2.0 license

package verification

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"time"

	"golang.org/x/exp/slices"
)

var (
	OidExtensionKeyUsage               = asn1.ObjectIdentifier{2, 5, 29, 15}
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

type BasicConstraints struct {
	IsCA              bool `asn1:"boolean"`
	PathLenConstraint int  `asn1:"optional"`
}

// A tcg-dice-MultiTcbInfo extension.
// This extension SHOULD be marked as critical.
func getMultiTcbInfo(extensions []pkix.Extension) (TcgMultiTcbInfo, error) {
	var multiTcbInfo TcgMultiTcbInfo
	for _, ext := range extensions {
		if ext.Id.Equal(OidExtensionTcgDiceMultiTcbInfo) {
			if !ext.Critical {
				return multiTcbInfo, fmt.Errorf("TCG DICE MultiTcbInfo extension is not marked as CRITICAL")
			}
			_, err := asn1.Unmarshal(ext.Value, &multiTcbInfo)
			if err != nil {
				return multiTcbInfo, fmt.Errorf("Failed to unmarshal MultiTcbInfo field: %v", err)
			}
			break
		}
	}
	return multiTcbInfo, nil
}

func getBasicConstraints(extensions []pkix.Extension) (BasicConstraints, error) {
	var bc BasicConstraints
	for _, ext := range extensions {
		if ext.Id.Equal(OidExtensionBasicConstraints) {
			if !ext.Critical {
				return bc, fmt.Errorf("BasicConstraints extension is not marked as CRITICAL")
			}
			_, err := asn1.Unmarshal(ext.Value, &bc)
			if err != nil {
				return bc, fmt.Errorf("Failed to unmarshal BasicConstraints extension: %v", err)
			}
			break
		}
	}
	return bc, nil
}

func getUeid(extensions []pkix.Extension) (TcgUeidExtension, error) {
	var ueid TcgUeidExtension
	for _, ext := range extensions {
		if ext.Id.Equal(OidExtensionTcgDiceUeid) {
			if !ext.Critical {
				return ueid, fmt.Errorf("UEID extension is not marked as CRITICAL")
			}
			_, err := asn1.Unmarshal(ext.Value, &ueid)
			if err != nil {
				return ueid, fmt.Errorf("Failed to unmarshal UEID extension: %v", err)
			}
			break
		}
	}
	return ueid, nil
}

func getExtendedKeyUsages(extensions []pkix.Extension) ([]asn1.ObjectIdentifier, error) {
	var eku []asn1.ObjectIdentifier
	for _, ext := range extensions {
		if ext.Id.Equal(OidExtensionExtKeyUsage) {
			if !ext.Critical {
				return eku, fmt.Errorf("ExtKeyUsage extension is not marked as CRITICAL")
			}
			_, err := asn1.Unmarshal(ext.Value, &eku)
			if err != nil {
				return eku, fmt.Errorf("Failed to unmarshal ExtKeyUsage extension: %v", err)
			}
			break
		}
	}
	return eku, nil
}

func getKeyUsage(extensions []pkix.Extension) (x509.KeyUsage, error) {
	var usageBits asn1.BitString
	for _, ext := range extensions {
		if ext.Id.Equal(OidExtensionKeyUsage) {
			if !ext.Critical {
				return x509.KeyUsage(0), fmt.Errorf("KeyUsage extension is not marked as CRITICAL")
			}
			_, err := asn1.Unmarshal(ext.Value, &usageBits)
			if err != nil {
				return x509.KeyUsage(0), fmt.Errorf("Failed to unmarshal KeyUsage extension: %v", err)
			}
			break
		}
	}

	var usage int
	for i := 0; i < 9; i++ {
		if usageBits.At(i) != 0 {
			usage |= 1 << uint(i)
		}
	}
	return x509.KeyUsage(usage), nil
}

func getTcbInfoForHandle(c DPEClient, handle *ContextHandle) (*ContextHandle, DiceTcbInfo, error) {
	outHandle := handle

	// Get digest size
	profile, err := c.GetProfile()
	if err != nil {
		return outHandle, DiceTcbInfo{}, fmt.Errorf("Cannot get profile: %s", err)
	}

	digestLen := profile.Profile.GetDigestSize()
	label := make([]byte, digestLen)

	certifiedKey, err := c.CertifyKey(outHandle, label, CertifyKeyX509, 0)
	if err != nil {
		return outHandle, DiceTcbInfo{}, fmt.Errorf("Could not certify key: %s", err)
	}

	outHandle = &certifiedKey.Handle
	leafCertBytes := certifiedKey.Certificate

	var leafCert *x509.Certificate

	// Check whether certificate is DER encoded.
	if leafCert, err = x509.ParseCertificate(leafCertBytes); err != nil {
		return outHandle, DiceTcbInfo{}, err
	}

	// Get DICE information from MultiTcbInfo Extension
	multiTcbInfo, err := getMultiTcbInfo(leafCert.Extensions)
	if err != nil {
		return outHandle, DiceTcbInfo{}, err
	}

	if len(multiTcbInfo) == 0 {
		return outHandle, DiceTcbInfo{}, fmt.Errorf("Certificate MutliTcbInfo is empty")
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
			msg += fmt.Errorf("Certificate \"%s\" has unhandled critical extension \"%s\"", certSubject, ext).Error()
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
			msg += fmt.Errorf("Certificate \"%s\" has unhandled critical extension \"%s\"", certSubject, ext).Error()
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}

// Checks whether the VendorInfo is 4-bytes TARGET_LOCALITY parameter
func checkDiceTcbVendorInfo(currentTcbInfo DiceTcbInfo, targetLocality uint32) error {
	var err error
	expectedVendorInfo := make([]byte, 4)
	binary.BigEndian.PutUint32(expectedVendorInfo, targetLocality)
	if !bytes.Equal(currentTcbInfo.VendorInfo, expectedVendorInfo) {
		err = fmt.Errorf("Unexpected VendorInfo for current DICE TCB block, want %v but got %v", expectedVendorInfo, currentTcbInfo.VendorInfo)
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
		err = fmt.Errorf("Unexpected TCI type for current DICE TCB block, want %v but got %v", expectedTciTypeBytes, currentTcbInfo.Type)
	}
	return err
}

// Checks whether the Hash Algorithm field in FWID block is correct
func checkDiceTcbHashAlgorithm(currentTcbInfo DiceTcbInfo, hashAlg asn1.ObjectIdentifier) error {
	for _, fwid := range currentTcbInfo.Fwids {
		if !fwid.HashAlg.Equal(hashAlg) {
			return fmt.Errorf("Unexpected hash algorithm in FWID block, expected %s but got %s", hashAlg, fwid.HashAlg)
		}
	}
	return nil
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
		return fmt.Errorf("Error verifying DPE leaf: %s", err.Error())
	}

	// Log certificate chains linked to leaf
	if len(chains) != 1 {
		return fmt.Errorf("Unexpected number of cert chains: %d", len(chains))
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
			return nil, fmt.Errorf("Found a self-signed certificate in middle of certificate chain returned by GetCertificateChain")
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
		err = fmt.Errorf("Unexpected TCI_CURRENT digest, want %v but got %v", wantCurrentTCI, currentTCI)
	}

	// Check TCI_CUMULATIVE against expected cumulative TCI
	wantCumulativeTCI := computeExpectedCumulative(lastCumulativeTCI, currentTCI)
	cumulativeTCI := tcbInfo.Fwids[1].Digest
	if !bytes.Equal(cumulativeTCI, wantCumulativeTCI) {
		err = fmt.Errorf("Unexpected TCI_CUMULATIVE value, want %v but got %v", wantCumulativeTCI, cumulativeTCI)
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
	if multiTcbInfo, err = getMultiTcbInfo(leafCert.Extensions); err != nil {
		return err
	}

	if len(multiTcbInfo) == 0 {
		return fmt.Errorf("Certificate MutliTcbInfo is empty")
	}

	// Calculate expected cumulative value
	defaultTci := make([]byte, digestLen)

	// Check cumulative, current TCI at the last index of  multitcb info
	// It must have default TCI value
	lastIndex := len(multiTcbInfo) - 1
	if !bytes.Equal(multiTcbInfo[lastIndex].Fwids[0].Digest, defaultTci) {
		return fmt.Errorf("Current TCI value for first TCB block, want %v but got %v", defaultTci, multiTcbInfo[lastIndex].Fwids[0].Digest)
	}

	if !bytes.Equal(multiTcbInfo[lastIndex].Fwids[1].Digest, defaultTci) {
		return fmt.Errorf("Cumulative TCI value for first TCB block, want %v but got %v", defaultTci, multiTcbInfo[lastIndex].Fwids[1].Digest)
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