// Licensed under the Apache-2.0 license

package verification

import (
	"errors"
	"testing"
)

func TestRotateContextHandle(d TestDPEInstance, c DPEClient, t *testing.T) {
	testRotateContextHandle(d, c, t, false)
}

func TestRotateContextHandleSimulation(d TestDPEInstance, c DPEClient, t *testing.T) {
	testRotateContextHandle(d, c, t, true)
}

func testRotateContextHandle(d TestDPEInstance, c DPEClient, t *testing.T, simulation bool) {
	handle := getInitialContextHandle(d, c, t, simulation)
	defer func() {
		if simulation {
			c.DestroyContext(handle, DestroyDescendants)
		}
	}()

	// Check handle rotated is non-default when no flags are set
	handle = testWithoutTargetDefaultFlag(d, c, t, handle)

	// Check handle is rotated to default handle in default context and error is reported in simulated context
	testWithTargetDefaultFlag(d, c, t, handle, simulation)
}

// Checks whether the default context handle is rotated to a some other context handle
func testWithoutTargetDefaultFlag(d TestDPEInstance, c DPEClient, t *testing.T, handle *ContextHandle) *ContextHandle {
	rotatedContext, err := c.RotateContextHandle(handle, RotateContextHandleFlags(0))
	if err != nil {
		t.Fatalf("[FATAL]: Could not rotate context handle: %v", err)
	}

	if *rotatedContext == DefaultContextHandle {
		t.Errorf("[ERROR]: Expected random context handle but have got default context %v", rotatedContext)
	}

	return rotatedContext
}

// Checks whether the context handle is rotated to default context.
// In simulated context, the rotated handle cannot be made default context handle as a mixture of default and
// non-default context handles are not allowed.
// In default context, the rotated handle can be made default context handle when there is no default context handle already.
func testWithTargetDefaultFlag(d TestDPEInstance, c DPEClient, t *testing.T, handle *ContextHandle, simulation bool) {
	if simulation {
		_, err := c.RotateContextHandle(handle, TargetIsDefault)
		if err == nil {
			t.Fatalf("[FATAL]: Should return %q for simulation context, but returned no error", StatusInvalidArgument)
		} else if !errors.Is(err, StatusInvalidArgument) {
			t.Fatalf("[FATAL]: Incorrect error type. Should return %q, but returned %q", StatusInvalidArgument, err)
		}
	} else {
		rotatedDefaultContext, err := c.RotateContextHandle(handle, TargetIsDefault)
		if err != nil {
			t.Fatalf("[FATAL]: Could not rotate context handle: %v", err)
		}

		// Check whether the rotated context handle is default context handle
		if *rotatedDefaultContext != DefaultContextHandle {
			t.Errorf("[ERROR]: TARGET_IS_DEFAULT is set, have got %v but want %v", rotatedDefaultContext, DefaultContextHandle)
		}

		// Check whether error is reported when TARGET_IS_DEFAULT is set when a default context handle exists already.
		_, err = c.RotateContextHandle(rotatedDefaultContext, TargetIsDefault)
		if err == nil {
			t.Fatalf("[FATAL]: Should return %q for default context, but returned no error", StatusInvalidArgument)
		} else if !errors.Is(err, StatusInvalidArgument) {
			t.Fatalf("[FATAL]: Incorrect error type. Should return %q, but returned %q", StatusInvalidArgument, err)
		}
	}
}
