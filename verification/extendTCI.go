// Licensed under the Apache-2.0 license

package verification

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
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

	tciValue := make([]byte, digestLen)
	for i := range tciValue {
		tciValue[i] = byte(i)
	}

	handle, tcbInfo, err := getTcbInfoForHandle(c, handle)
	if err != nil {
		t.Fatal(err)
	}
	lastCumulative := tcbInfo.Fwids[1].Digest

	// Set current TCI value
	_, err = c.ExtendTCI(handle, tciValue)
	if err != nil {
		t.Fatalf("[FATAL]: Could not extend TCI: %v", err)
	}

	// Check current and cumulative measurement by CertifyKey
	expectedCumulative := computeExpectedCumulative(lastCumulative, tciValue)
	verifyMeasurements(c, t, handle, tciValue, expectedCumulative)
}

func computeExpectedCumulative(lastCumulative []byte, tciValue []byte) []byte {
	var hasher hash.Hash
	digestLen := len(lastCumulative)
	if digestLen == 32 {
		hasher = sha256.New()
	} else if digestLen == 48 {
		hasher = sha512.New384()
	}
	hasher.Write(lastCumulative)
	hasher.Write(tciValue)
	return hasher.Sum(nil)
}

// Check whether the ExtendTCI command with derived child context.
func TestExtendTciOnDerivedContexts(d TestDPEInstance, c DPEClient, t *testing.T) {
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
	tciValue := make([]byte, digestLen)
	for i := range tciValue {
		tciValue[i] = byte(i + 1)
	}

	extendTciValue := make([]byte, digestLen)
	for i := range extendTciValue {
		extendTciValue[i] = byte(i + 2)
	}

	// Preserve parent context to restore for subsequent tests.
	parentHandle, err := c.RotateContextHandle(handle, RotateContextHandleFlags(0))
	if err != nil {
		t.Errorf("[ERROR]: Error while rotating parent context handle, this may cause failure in subsequent tests: %s", err)
	}

	// Change parent back to default context
	defer func() {
		_, err = c.RotateContextHandle(parentHandle, RotateContextHandleFlags(TargetIsDefault))
		if err != nil {
			t.Errorf("[ERROR]: Error while restoring parent context handle as default context handle, this may cause failure in subsequent tests: %s", err)
		}
	}()

	// Derive Child context with input data, tag it and check TCI_CUMULATIVE
	childCtx, err := c.DeriveChild(parentHandle, tciValue, DeriveChildFlags(RetainParent|InputAllowX509), 0, 0)
	if err != nil {
		t.Fatalf("[FATAL]: Error while creating default child handle in default context: %s", err)
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

	childHandle, childTcbInfo, err := getTcbInfoForHandle(c, childHandle)
	if err != nil {
		t.Fatalf("[FATAL]: Could not get TcbInfo: %v", err)
	}

	if !bytes.Equal(childTcbInfo.Fwids[0].Digest, tciValue) {
		t.Errorf("[ERROR]: Got current TCI %x, expected %x", childTcbInfo.Fwids[0].Digest, tciValue)
	}

	// Check TCI_CUMULATIVE after creating child context
	wantCumulativeTCI := computeExpectedCumulative(make([]byte, digestLen), childTcbInfo.Fwids[0].Digest)
	if !bytes.Equal(childTcbInfo.Fwids[1].Digest, wantCumulativeTCI) {
		t.Errorf("[ERROR]: Child node's cumulative TCI %x, expected %x", childTcbInfo.Fwids[1].Digest, wantCumulativeTCI)
	}

	// Set current TCI value
	lastCumulative := childTcbInfo.Fwids[1].Digest
	childHandle, err = c.ExtendTCI(childHandle, extendTciValue)
	if err != nil {
		t.Fatalf("[FATAL]: Could not extend TCI: %v", err)
	}

	childHandle, childTcbInfo, err = getTcbInfoForHandle(c, childHandle)
	if err != nil {
		t.Fatalf("[FATAL]: Could not get TcbInfo: %v", err)
	}

	if !bytes.Equal(childTcbInfo.Fwids[0].Digest, extendTciValue) {
		t.Errorf("[ERROR]: Got current TCI %x, expected %x", childTcbInfo.Fwids[0].Digest, extendTciValue)
	}

	wantCumulativeTCI = computeExpectedCumulative(lastCumulative, extendTciValue)
	if !bytes.Equal(childTcbInfo.Fwids[1].Digest, wantCumulativeTCI) {
		t.Errorf("[ERROR]: Child node's cumulative TCI %x, expected %x", childTcbInfo.Fwids[1].Digest, wantCumulativeTCI)
	}
}

func verifyMeasurements(c DPEClient, t *testing.T, handle *ContextHandle, expectedCurrent []byte, expectedCumulative []byte) {
	handle, tcbInfo, err := getTcbInfoForHandle(c, handle)
	if err != nil {
		t.Fatal(err)
	}

	// Check that the last TcbInfo current/cumulative are as expected
	current := tcbInfo.Fwids[0].Digest
	cumulative := tcbInfo.Fwids[1].Digest
	if !bytes.Equal(current, expectedCurrent) {
		t.Errorf("[ERROR]: Unexpected TCI_CURRENT digest, want %v but got %v", expectedCurrent, current)
	}

	if !bytes.Equal(cumulative, expectedCumulative) {
		t.Errorf("[ERROR]: Unexpected cumulative TCI value, want %v but got %v", expectedCumulative, cumulative)
	}
}
