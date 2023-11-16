// Licensed under the Apache-2.0 license

package verification

import (
	"errors"
	"testing"
)

// Check tagTCI command with default context handle.
func TestTagTCI(d TestDPEInstance, c DPEClient, t *testing.T) {
	var err error
	useSimulation := false // To indicate that simulation context is not used

	// Get default context handle
	handle := getInitialContextHandle(d, c, t, useSimulation)

	// Check to see our tag is not yet found and then tag default context
	if _, err := c.GetTaggedTCI(defaultCtxTCITag); !errors.Is(err, StatusBadTag) {
		t.Fatalf("GetTaggedTCI returned %v, want %v", err, StatusBadTag)
	}

	// Tag default context handle and make sure default handle returns
	// same handle when used for tagging TCI
	newHandle, err := c.TagTCI(handle, defaultCtxTCITag)
	if err != nil {
		t.Fatalf("Could not tag TCI: %v", err)
	}
	if *newHandle != *handle {
		t.Errorf("New context handle from TagTCI was %x, expected %x", newHandle, handle)
	}

	_, err = c.GetTaggedTCI(defaultCtxTCITag)
	if err != nil {
		t.Fatalf("Could not get tagged TCI: %v", err)
	}

	// Retag a tagged TCI should report error
	newTag := TCITag(11111)
	if _, err := c.TagTCI(handle, newTag); !errors.Is(err, StatusBadTag) {
		t.Fatalf("Re-tagging a tagged TCI returned %v, want %v", err, StatusBadTag)
	}

	// Fetching a non-existent tag should report error
	if _, err := c.GetTaggedTCI(TCITag(nonExistentTCITag)); !errors.Is(err, StatusBadTag) {
		t.Fatalf("GetTaggedTCI returned %v, want %v", err, StatusBadTag)
	}
}
