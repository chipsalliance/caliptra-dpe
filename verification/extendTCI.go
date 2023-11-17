// Licensed under the Apache-2.0 license

package verification

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"hash"

	"testing"
)

// Check whether the ExtendTCI command updates the current TCI and cumulative TCI.
func TestExtendTCI(d TestDPEInstance, c DPEClient, t *testing.T) {
	var err error
	useSimulation := false // To indicate that simulation context is not used

	// Get default context handle
	handle := getInitialContextHandle(d, c, t, useSimulation)

	// Get digest size
	profile, err := GetTransportProfile(d)
	if err != nil {
		t.Fatalf("[FATAL]: Could not get profile: %v", err)
	}
	digestLen := profile.GetDigestSize()

	// Initialize TCI inputs with all zeroes
	// since, TCI_DEFAULT for default context is all zeroes
	defaultTci := make([]byte, digestLen)

	// Initialize hasher
	var hasher hash.Hash
	if digestLen == 32 {
		hasher = sha256.New()
	} else if digestLen == 48 {
		hasher = sha512.New384()
	}

	tciValue := make([]byte, digestLen)
	for i := range tciValue {
		tciValue[i] = byte(i)
	}

	// Set current TCI value
	_, err = c.ExtendTCI(handle, tciValue)
	if err != nil {
		t.Fatalf("[FATAL]: Could not extend TCI: %v", err)
	}

	// Cross-check current and cumulative measurement by CertifyKey
	verifyMeasurementsByCertifyKey(c, t, handle, defaultTci, tciValue, hasher)
}

func verifyMeasurementsByCertifyKey(c DPEClient, t *testing.T, handle *ContextHandle, label []byte, tciValue []byte, hasher hash.Hash) {
	certifiedKey, err := c.CertifyKey(handle, label, CertifyKeyX509, 0)
	if err != nil {
		t.Fatalf("[FATAL]: Could not get Certified key: %v", err)
	}

	leafCertBytes := certifiedKey.Certificate

	var leafCert *x509.Certificate

	// Check whether certificate is DER encoded.
	if leafCert, err = x509.ParseCertificate(leafCertBytes); err != nil {
		t.Fatalf("[FATAL]: Could not parse certificate using crypto/x509: %v", err)
	}

	// Get DICE information from MultiTcbInfo Extension
	multiTcbInfo, err := checkCertifyKeyMultiTcbInfoExtensionStructure(t, leafCert)
	if err != nil {
		t.Errorf("Error while unmarshalling MultiTCB information %v, skipping MultiTCB validation", err)
	} else {
		// Cross-verify cumulative value returned in MultiTcbInfo
		checkCurrentDiceTcbMeasurements(t, multiTcbInfo, tciValue)
	}
}
