// Licensed under the Apache-2.0 license

package verification

import (
	"bytes"
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
	verifyMeasurementsByCertifyKey(c, t, handle, defaultTci, tciValue, false, hasher)
}

// Check whether the ExtendTCI command with derived child context.
func TestExtendTciOnDerivedContexts(d TestDPEInstance, c DPEClient, t *testing.T) {
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

	// Initialize TCI inputs
	parentTciValue := make([]byte, digestLen)
	for i := range parentTciValue {
		parentTciValue[i] = byte(i)
	}

	deriveCtxTciValue := make([]byte, digestLen)
	for i := range deriveCtxTciValue {
		deriveCtxTciValue[i] = byte(i + 1)
	}

	extendTciValue := make([]byte, digestLen)
	for i := range extendTciValue {
		extendTciValue[i] = byte(i + 2)
	}

	// Initialize hasher
	var hasher hash.Hash
	if digestLen == 32 {
		hasher = sha256.New()
	} else if digestLen == 48 {
		hasher = sha512.New384()
	}

	// Cross-check current and cumulative measurement by CertifyKey of parent context handle
	handle, _ = verifyMeasurementsByCertifyKey(c, t, handle, make([]byte, digestLen), parentTciValue, false, hasher)

	// Preserve parent context to restore for subsequent tests.
	parentHandle, err := c.RotateContextHandle(handle, RotateContextHandleFlags(0))
	if err != nil {
		t.Errorf("[ERROR]: Error while rotating parent context handle, this may cause failure in subsequent tests: %s", err)
	}

	// Derive Child context with input data, tag it and check TCI_CUMULATIVE
	childCtx, err := c.DeriveChild(parentHandle, deriveCtxTciValue, DeriveChildFlags(RetainParent|InputAllowX509), 0, 0)
	if err != nil {
		t.Fatalf("[FATAL]: Error while creating default child handle in default context: %s", err)
	}

	// Cross-check current and cumulative measurement by CertifyKey of derived context context
	newHandle, derivedTciMultiTcbInfo := verifyMeasurementsByCertifyKey(c, t, &childCtx.NewContextHandle, make([]byte, digestLen), deriveCtxTciValue, false, hasher)

	// Extend TCI to child context and check TCI_CURRENT and TCI_CUMULATIVE
	newHandle, err = c.ExtendTCI(newHandle, extendTciValue)
	if err != nil {
		t.Fatalf("[FATAL]: Could not extend tag: %v", err)
	}

	// Cross-check current and cumulative measurement by CertifyKey of parent context handle
	newHandle, extendedTCiMultiTcbInfo := verifyMeasurementsByCertifyKey(c, t, newHandle, make([]byte, digestLen), extendTciValue, true, hasher)

	cumulativeTci := extendedTCiMultiTcbInfo[0].Fwids[1].Digest
	prevCumulativeTci := derivedTciMultiTcbInfo[0].Fwids[1].Digest

	// Re-initialize hasher
	hasher.Reset()

	// Recompute hash
	hasher.Write(prevCumulativeTci)
	hasher.Write(extendTciValue)
	expectedCumulativeValue := hasher.Sum(nil)

	// Verify hash
	if !bytes.Equal(cumulativeTci, expectedCumulativeValue) {
		t.Errorf("[ERROR]: Unexpected cumulative value for extended TCI, want %v but got %v", expectedCumulativeValue, cumulativeTci)
	}

	// Clean up derived context and restore default context handle for subsequent tests
	defer func() {
		err := c.DestroyContext(newHandle, DestroyDescendants)
		if err != nil {
			t.Errorf("[ERROR]: Error while cleaning up derived context, this may cause failure in subsequent tests: %s", err)
		}

		_, err = c.RotateContextHandle(&childCtx.ParentContextHandle, RotateContextHandleFlags(TargetIsDefault))
		if err != nil {
			t.Errorf("[ERROR]: Error while restoring parent context handle as default context handle, this may cause failure in subsequent tests: %s", err)
		}
	}()

}

func verifyMeasurementsByCertifyKey(c DPEClient, t *testing.T, handle *ContextHandle, label []byte, tciValue []byte, isTciExtended bool, hasher hash.Hash) (*ContextHandle, []DiceTcbInfo) {
	t.Helper()
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
		checkCurrentDiceTcbMeasurements(t, handle, multiTcbInfo, tciValue, isTciExtended)
	}
	return &certifiedKey.Handle, multiTcbInfo
}
