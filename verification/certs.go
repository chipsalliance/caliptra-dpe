// Licensed under the Apache-2.0 license

package verification

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

// This file is used to test the certify key command.
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

// BasicConstraints represents an X.509 BasicConstraints extension
type BasicConstraints struct {
	IsCA              bool `asn1`
	PathLenConstraint int  `asn1:"optional"`
}

// A tcg-dice-MultiTcbInfo extension.
// This extension SHOULD be marked as critical.
func getMultiTcbInfo(extensions []pkix.Extension) (TcgMultiTcbInfo, error) {
	var multiTcbInfo TcgMultiTcbInfo
	for _, ext := range extensions {
		if ext.Id.Equal(OidExtensionTcgDiceMultiTcbInfo) {
			if !ext.Critical {
				return multiTcbInfo, fmt.Errorf("[ERROR]: TCG DICE MultiTcbInfo extension is not marked as CRITICAL")
			}
			_, err := asn1.Unmarshal(ext.Value, &multiTcbInfo)
			if err != nil {
				return multiTcbInfo, fmt.Errorf("[ERROR]: Failed to unmarshal MultiTcbInfo field: %v", err)
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
				return bc, fmt.Errorf("[ERROR]: BasicConstraints extension is not marked as CRITICAL")
			}
			_, err := asn1.Unmarshal(ext.Value, &bc)
			if err != nil {
				return bc, fmt.Errorf("[ERROR]: Failed to unmarshal BasicConstraints extension: %v", err)
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
				return ueid, fmt.Errorf("[ERROR]: UEID extension is not marked as CRITICAL")
			}
			_, err := asn1.Unmarshal(ext.Value, &ueid)
			if err != nil {
				return ueid, fmt.Errorf("[ERROR]: Failed to unmarshal UEID extension: %v", err)
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
				return eku, fmt.Errorf("[ERROR]: ExtKeyUsage extension is not marked as CRITICAL")
			}
			_, err := asn1.Unmarshal(ext.Value, &eku)
			if err != nil {
				return eku, fmt.Errorf("[ERROR]: Failed to unmarshal ExtKeyUsage extension: %v", err)
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
				return x509.KeyUsage(0), fmt.Errorf("[ERROR]: KeyUsage extension is not marked as CRITICAL")
			}
			_, err := asn1.Unmarshal(ext.Value, &usageBits)
			if err != nil {
				return x509.KeyUsage(0), fmt.Errorf("[ERROR]: Failed to unmarshal KeyUsage extension: %v", err)
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
		return outHandle, DiceTcbInfo{}, fmt.Errorf("Certificate MultiTcbInfo is empty")
	}

	return outHandle, multiTcbInfo[0], nil
}
