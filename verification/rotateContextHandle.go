// Licensed under the Apache-2.0 license

package verification

import (
	"errors"
	"testing"
)

// TestRotateContextHandle tests the RotateContextHandle command
func TestRotateContextHandle(d TestDPEInstance, c DPEClient, t *testing.T) {
	simulation := false
	handle := getInitialContextHandle(d, c, t, simulation)

	// Check whether the rotated context handle is a random context handle
	handle, err := c.RotateContextHandle(handle, RotateContextHandleFlags(0))
	if err != nil {
		t.Fatalf("[FATAL]: Could not rotate context handle: %v", err)
	}
	if *handle == DefaultContextHandle {
		t.Errorf("[ERROR]: Expected random context handle but have got default context %v", handle)
	}

	// Rotate back the handle to default handle for subsequent tests
	// This works only when there is no default handle available
	handle, err = c.RotateContextHandle(handle, TargetIsDefault)
	if err != nil {
		t.Fatalf("[FATAL]: Could not rotate context handle: %v", err)
	}
	if *handle != DefaultContextHandle {
		t.Errorf("[ERROR]: TARGET_IS_DEFAULT is set, have got %v but want %v", handle, DefaultContextHandle)
	}

	// Check for error when a default context handle exists already and handle is rotated to default handle
	// Since, there cannot be more than one default context handle
	_, err = c.RotateContextHandle(handle, TargetIsDefault)
	if err == nil {
		t.Fatalf("[FATAL]: Should return %q for default context, but returned no error", StatusInvalidArgument)
	} else if !errors.Is(err, StatusInvalidArgument) {
		t.Fatalf("[FATAL]: Incorrect error type. Should return %q, but returned %q", StatusInvalidArgument, err)
	}
}

// TestRotateContextHandleSimulation tests calling RotateContextHandle on
// simulation contexts
func TestRotateContextHandleSimulation(d TestDPEInstance, c DPEClient, t *testing.T) {
	simulation := true
	handle := getInitialContextHandle(d, c, t, simulation)
	defer func() {
		c.DestroyContext(handle, DestroyDescendants)
	}()

	// Check whether the rotated context handle is a random context handle
	handle, err := c.RotateContextHandle(handle, RotateContextHandleFlags(0))
	if err != nil {
		t.Fatalf("[FATAL]: Could not rotate context handle: %v", err)
	}
	if *handle == DefaultContextHandle {
		t.Errorf("[ERROR]: Expected random context handle but have got default context %v", handle)
	}

	// In simulated context, the handle cannot be rotated to default handle
	// Since, it is not allowed to have a both of default and non-default context handles together
	_, err = c.RotateContextHandle(handle, TargetIsDefault)
	if err == nil {
		t.Fatalf("[FATAL]: Should return %q for simulation context, but returned no error", StatusInvalidArgument)
	} else if !errors.Is(err, StatusInvalidArgument) {
		t.Fatalf("[FATAL]: Incorrect error type. Should return %q, but returned %q", StatusInvalidArgument, err)
	}
}
