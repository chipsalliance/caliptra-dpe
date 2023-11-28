// Licensed under the Apache-2.0 license

package verification

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

// A tcg-dice-MultiTcbInfo extension.
// This extension SHOULD be marked as critical.
func getMultiTcbInfo(c *x509.Certificate) (TcgMultiTcbInfo, error) {
	var multiTcbInfo TcgMultiTcbInfo

	// Check MultiTcbInfo Extension
	//tcg-dice-MultiTcbInfo extension
	for _, ext := range c.Extensions {
		if ext.Id.Equal(OidExtensionTcgDiceMultiTcbInfo) { // OID for Tcg Dice MultiTcbInfo
			if !ext.Critical {
				return multiTcbInfo, fmt.Errorf("[ERROR]: TCG DICE MultiTcbInfo extension is not marked as CRITICAL")
			}
			_, err := asn1.Unmarshal(ext.Value, &multiTcbInfo)
			if err != nil {
				// multiTcb info is not provided in leaf
				return multiTcbInfo, fmt.Errorf("[ERROR]: Failed to unmarshal MultiTcbInfo field: %v", err)
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
	multiTcbInfo, err := getMultiTcbInfo(leafCert)
	if err != nil {
		return outHandle, DiceTcbInfo{}, err
	}

	if len(multiTcbInfo) == 0 {
		return outHandle, DiceTcbInfo{}, fmt.Errorf("Certificate MutliTcbInfo is empty")
	}

	return outHandle, multiTcbInfo[0], nil
}
