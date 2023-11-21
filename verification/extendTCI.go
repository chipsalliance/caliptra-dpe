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

	tcbInfo, err := getTcbInfoForHandle(c, handle)
	if err != nil {
		t.Fatal(err)
	}
	lastCumulative := tcbInfo.Fwids[1].Digest

	// Set current TCI value
	_, err = c.ExtendTCI(handle, tciValue)
	if err != nil {
		t.Fatalf("[FATAL]: Could not extend TCI: %v", err)
	}

	// Compute expected cumulative
	var hasher hash.Hash
	if digestLen == 32 {
		hasher = sha256.New()
	} else if digestLen == 48 {
		hasher = sha512.New384()
	}
	hasher.Write(lastCumulative)
	hasher.Write(tciValue)
	expectedCumulative := hasher.Sum(nil)

	// Cross-check current and cumulative measurement by CertifyKey
	verifyMeasurements(c, t, handle, tciValue, expectedCumulative)
}

func verifyMeasurements(c DPEClient, t *testing.T, handle *ContextHandle, expectedCurrent []byte, expectedCumulative []byte) {
	tcbInfo, err := getTcbInfoForHandle(c, handle)
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
