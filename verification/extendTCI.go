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

	// Cross-check current and cumulative measurement by GetTaggedTCI
	verifyMeasurementsByGetTaggedTCI(c, t, defaultTci, tciValue, hasher)

	// Cross-check current and cumulative measurement by CertifyKey
	verifyMeasurementsByCertifyKey(c, t, handle, defaultTci, tciValue, hasher)
}

// Check whether the ExtendTCI command with derived child context.
func TestExtendTciOnDerivedContexts(d TestDPEInstance, c DPEClient, t *testing.T) {
	var err error
	var wantCumulativeTCI []byte

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
	defaultTci := make([]byte, digestLen)

	tciValue := make([]byte, digestLen)
	for i := range tciValue {
		tciValue[i] = byte(i + 1)
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

	// Get parent context TCI values for cumulative value calculation
	parentTci, err := c.GetTaggedTCI(defaultCtxTCITag)
	if err != nil {
		t.Fatalf("[FATAL]: Could not get tagged TCI: %v", err)
	}

	// Cross-verify parent's TCI_CUMULATIVE
	hasher.Write(defaultTci)
	hasher.Write(parentTci.CurrentTCI)
	wantCumulativeTCI = hasher.Sum(nil)
	if !bytes.Equal(parentTci.CumulativeTCI, wantCumulativeTCI) {
		t.Errorf("[ERROR]: Parent node's cumulative TCI %x, expected %x", parentTci.CumulativeTCI, wantCumulativeTCI)
	}

	// Preserve parent context to restore for subsequent tests.
	parentHandle, err := c.RotateContextHandle(handle, RotateContextHandleFlags(0))
	if err != nil {
		t.Errorf("[ERROR]: Error while rotating parent context handle, this may cause failure in subsequent tests: %s", err)
	}

	// Derive Child context with input data, tag it and check TCI_CUMULATIVE
	childCtx, err := c.DeriveChild(parentHandle, tciValue, DeriveChildFlags(RetainParent), 0, 0)
	if err != nil {
		t.Fatalf("[FATAL]: Error while creating default child handle in default context: %s", err)
	}

	// Tag derived context
	newHandle, err := c.TagTCI(&childCtx.NewContextHandle, childCtxTCITag)
	if err != nil {
		t.Fatalf("[FATAL]: Could not tag TCI: %v", err)
	}

	childTci, err := c.GetTaggedTCI(childCtxTCITag)
	if err != nil {
		t.Fatalf("[FATAL]: Could not get tagged TCI: %v", err)
	}

	if !bytes.Equal(childTci.CurrentTCI, tciValue) {
		t.Errorf("[ERROR]: GetTaggedTCI returned current TCI %x, expected %x", childTci.CurrentTCI, tciValue)
	}

	// Check TCI_CUMULATIVE after creating child context
	hasher.Reset()
	hasher.Write(defaultTci)
	hasher.Write(childTci.CurrentTCI)
	wantCumulativeTCI = hasher.Sum(nil)
	if !bytes.Equal(childTci.CumulativeTCI, wantCumulativeTCI) {
		t.Errorf("[ERROR]: Child node's cumulative TCI %x, expected %x", childTci.CumulativeTCI, wantCumulativeTCI)
	}

	// Extend TCI to child context and check TCI_CURRENT and TCI_CUMULATIVE
	newHandle, err = c.ExtendTCI(newHandle, extendTciValue)
	if err != nil {
		t.Fatalf("[FATAL]: Could not tag TCI: %v", err)
	}

	childExtendTci, err := c.GetTaggedTCI(childCtxTCITag)
	if err != nil {
		t.Fatalf("[FATAL]: Could not get tagged TCI: %v", err)
	}

	if !bytes.Equal(childExtendTci.CurrentTCI, extendTciValue) {
		t.Errorf("[ERROR]: GetTaggedTCI returned current TCI %x, expected %x", childExtendTci.CurrentTCI, extendTciValue)
	}

	// Check TCI_CUMULATIVE after extending input to child context
	hasher.Reset()
	hasher.Write(childTci.CumulativeTCI)
	hasher.Write(childExtendTci.CurrentTCI)
	wantCumulativeTCI = hasher.Sum(nil)
	if !bytes.Equal(childExtendTci.CumulativeTCI, wantCumulativeTCI) {
		t.Errorf("[ERROR]: Child node's cumulative TCI %x, expected %x", childExtendTci.CumulativeTCI, wantCumulativeTCI)
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

func verifyMeasurementsByGetTaggedTCI(c DPEClient, t *testing.T, defaultTci []byte, tciValue []byte, hasher hash.Hash) {
	taggedTCI, err := c.GetTaggedTCI(defaultCtxTCITag)
	if err != nil {
		t.Fatalf("[FATAL]: Could not get tagged TCI: %v", err)
	}

	// Check TCI_CURRENT
	wantCurrentTCI := tciValue
	if !bytes.Equal(taggedTCI.CurrentTCI, tciValue) {
		t.Errorf("[ERROR]: GetTaggedTCI returned current TCI %x, expected %x", taggedTCI.CurrentTCI, wantCurrentTCI)
	}

	// Cross-verify TCI_CUMULATIVE
	hasher.Write(defaultTci)
	hasher.Write(taggedTCI.CurrentTCI)
	if wantCumulativeTCI := hasher.Sum(nil); !bytes.Equal(taggedTCI.CumulativeTCI, wantCumulativeTCI) {
		t.Errorf("[ERROR]: GetTaggedTCI returned cumulative TCI %x, expected %x", taggedTCI.CumulativeTCI, wantCumulativeTCI)
	}
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
