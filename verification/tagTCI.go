// Licensed under the Apache-2.0 license

package verification

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"

	//"reflect"
	"testing"
)

// This file is used to test the tagTCI command.

func TestTagTCI(d TestDPEInstance, c DPEClient, t *testing.T) {
	var err error
	useSimulation := false // To indicate that simulation context is not used

	// Tag the default context
	handle := getInitialContextHandle(d, c, t, useSimulation)

	// Get digest size
	profile, err := GetTransportProfile(d)
	if err != nil {
		t.Fatalf("Could not get profile: %v", err)
	}

	digestLen := profile.GetDigestSize()

	tag := TCITag(12345)
	// Check to see our tag is not yet found.
	if _, err := c.GetTaggedTCI(tag); !errors.Is(err, StatusBadTag) {
		t.Fatalf("GetTaggedTCI returned %v, want %v", err, StatusBadTag)
	}

	// Make sure default handle returns same handle when extended
	testTagTCIHandle(d, c, t, handle, digestLen, tag)

	// Make sure the current TCI is updated
	// For profiles which use auto-initialization, we don't know the expected TCIs so we can check only current TCI
	testCurrentAndCumulativeTCI(d, c, t, handle, digestLen, tag)

	// Make sure some other tag is still not found.
	if _, err := c.GetTaggedTCI(TCITag(98765)); !errors.Is(err, StatusBadTag) {
		t.Fatalf("GetTaggedTCI returned %v, want %v", err, StatusBadTag)
	}

	// Pass TCI input to DerivedChild context and check cumulative TCI
	testForDerivedChildContexts(d, c, t, handle, digestLen, tag)
}

// Checks whether the default handle remains unchanged when extended with TCI value.
func testTagTCIHandle(d TestDPEInstance, c DPEClient, t *testing.T, handle *ContextHandle, digestLen int, tag TCITag) {
	tciValue := make([]byte, digestLen)
	for i := range tciValue {
		tciValue[i] = byte(i)
	}

	newHandle, err := c.TagTCI(handle, tag)
	if err != nil {
		t.Fatalf("Could not tag TCI: %v", err)
	}
	if *newHandle != *handle {
		t.Errorf("New context handle from TagTCI was %x, expected %x", newHandle, handle)
	}
}

// Checks whether the ExtendTCI command updates the current TCI and cumulative TCI.
func testCurrentAndCumulativeTCI(d TestDPEInstance, c DPEClient, t *testing.T, handle *ContextHandle, digestLen int, tag TCITag) {
	// Initialize TCI inputs
	defaultTci := make([]byte, digestLen)

	tciValue := make([]byte, digestLen)
	for i := range tciValue {
		tciValue[i] = byte(i)
	}

	// Initialize hasher
	var hasher hash.Hash
	if digestLen == 32 {
		hasher = sha256.New()
	} else if digestLen == 48 {
		hasher = sha512.New384()
	} else {
		t.Error("[ERROR]: Unsupported hash algorithm used for TCI value generation")
	}

	// Set current TCI value
	_, err := c.ExtendTCI(handle, tciValue)
	if err != nil {
		t.Fatalf("Could not tag TCI: %v", err)
	}

	taggedTCI, err := c.GetTaggedTCI(tag)
	if err != nil {
		t.Fatalf("Could not get tagged TCI: %v", err)
	}

	// Check TCI_CURRENT
	wantCurrentTCI := tciValue
	if !bytes.Equal(taggedTCI.CurrentTCI, tciValue) {
		t.Errorf("GetTaggedTCI returned current TCI %x, expected %x", taggedTCI.CurrentTCI, wantCurrentTCI)
	}

	// Cross-verify TCI_CUMULATIVE
	hasher.Write(defaultTci)
	hasher.Write(taggedTCI.CurrentTCI)
	if wantCumulativeTCI := hasher.Sum(nil); !bytes.Equal(taggedTCI.CumulativeTCI, wantCumulativeTCI) {
		t.Errorf("GetTaggedTCI returned cumulative TCI %x, expected %x", taggedTCI.CumulativeTCI, wantCumulativeTCI)
	}
}

// Checks whether the ExtendTCI command updates the current TCI.
func testForDerivedChildContexts(d TestDPEInstance, c DPEClient, t *testing.T, handle *ContextHandle, digestLen int, parentTag TCITag) {
	var wantCumulativeTCI []byte
	childTag := TCITag(23456)

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
	} else {
		t.Error("[ERROR]: Unsupported hash algorithm used for TCI value generation")
	}

	// Get parent context TCI values for cumulative value calculation
	parentTci, err := c.GetTaggedTCI(parentTag)
	if err != nil {
		t.Fatalf("Could not get tagged TCI: %v", err)
	}

	// Cross-verify parent's TCI_CUMULATIVE
	hasher.Write(defaultTci)
	hasher.Write(parentTci.CurrentTCI)
	wantCumulativeTCI = hasher.Sum(nil)
	if !bytes.Equal(parentTci.CumulativeTCI, wantCumulativeTCI) {
		t.Errorf("Parent node's cumulative TCI %x, expected %x", parentTci.CumulativeTCI, wantCumulativeTCI)
	}

	// Derive Child context with input data, tag it and check TCI_CUMULATIVE
	child, err := c.DeriveChild(handle, tciValue, DeriveChildFlags(MakeDefault), 0, 0)
	if err != nil {
		t.Fatalf("[FATAL]: Error while creating default child handle in default context: %s", err)
	}

	newHandle, err := c.TagTCI(&child.NewContextHandle, childTag)
	if err != nil {
		t.Fatalf("Could not tag TCI: %v", err)
	}

	childTci, err := c.GetTaggedTCI(childTag)
	if err != nil {
		t.Fatalf("Could not get tagged TCI: %v", err)
	}

	if !bytes.Equal(childTci.CurrentTCI, tciValue) {
		t.Errorf("GetTaggedTCI returned current TCI %x, expected %x", childTci.CurrentTCI, tciValue)
	}

	// Check TCI_CUMULATIVE after creating child context
	hasher.Reset()
	hasher.Write(defaultTci)
	hasher.Write(childTci.CurrentTCI)
	wantCumulativeTCI = hasher.Sum(nil)
	if !bytes.Equal(childTci.CumulativeTCI, wantCumulativeTCI) {
		t.Errorf("Child node's cumulative TCI %x, expected %x", childTci.CumulativeTCI, wantCumulativeTCI)
	}

	// Extend TCI to child context and check TCI_CURRENT and TCI_CUMULATIVE
	_, err = c.ExtendTCI(newHandle, extendTciValue)
	if err != nil {
		t.Fatalf("Could not tag TCI: %v", err)
	}

	childExtendTci, err := c.GetTaggedTCI(childTag)
	if err != nil {
		t.Fatalf("Could not get tagged TCI: %v", err)
	}

	if !bytes.Equal(childExtendTci.CurrentTCI, extendTciValue) {
		t.Errorf("GetTaggedTCI returned current TCI %x, expected %x", childExtendTci.CurrentTCI, extendTciValue)
	}

	// Check TCI_CUMULATIVE after extending input to child context
	hasher.Reset()
	hasher.Write(childTci.CumulativeTCI)
	hasher.Write(childExtendTci.CurrentTCI)
	wantCumulativeTCI = hasher.Sum(nil)
	if !bytes.Equal(childExtendTci.CumulativeTCI, wantCumulativeTCI) {
		t.Errorf("Child node's cumulative TCI %x, expected %x", childExtendTci.CumulativeTCI, wantCumulativeTCI)
	}
}
