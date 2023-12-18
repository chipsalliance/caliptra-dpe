// Licensed under the Apache-2.0 license

package verification

import (
	"errors"
	"testing"
)

// This file is used to test the initialize context command.

// TestInitializeContext tests calling InitializeContext
func TestInitializeContext(d TestDPEInstance, c DPEClient, t *testing.T) {
	for _, locality := range d.GetSupportedLocalities() {
		d.SetLocality(locality)
		testInitContext(d, c, t, false)
	}
}

// TestInitializeSimulation tests calling InitializeContext simulation mode
func TestInitializeSimulation(d TestDPEInstance, c DPEClient, t *testing.T) {
	for _, locality := range d.GetSupportedLocalities() {
		d.SetLocality(locality)
		testInitContext(d, c, t, true)
	}
}

func testInitContext(d TestDPEInstance, client DPEClient, t *testing.T, simulation bool) {
	// Try to create the default context if isn't done automatically.
	if !d.GetIsInitialized() {
		handle, err := client.InitializeContext(InitIsDefault)
		if err != nil {
			t.Fatalf("Failed to initialize default context: %v", err)
		}
		if *handle != ContextHandle([16]byte{0}) {
			t.Fatal("Incorrect default context handle.")
		}
		d.SetIsInitialized(true)
	}

	// Try to initialize another default context.
	_, err := client.InitializeContext(InitIsDefault)
	if err == nil {
		t.Fatal("The instance should return an error when trying to initialize another default context.")
	} else if !errors.Is(err, StatusArgumentNotSupported) {
		t.Fatalf("Incorrect error type. Should return %q, but returned %q", StatusArgumentNotSupported, err)
	}

	// Try to initialize a context that is neither default or simulation.
	_, err = client.InitializeContext(InitCtxFlags(0))
	if err == nil {
		t.Fatal("The instance should return an error when not default or simulation.")
	} else if !errors.Is(err, StatusInvalidArgument) {
		t.Fatalf("Incorrect error type. Should return %q, but returned %q", StatusInvalidArgument, err)
	}

	// TODO: test exhausting handles. This requires the ability to query how
	// many handles are currently in use.
	if simulation {
		handle, err := client.InitializeContext(InitIsSimulation)
		if err != nil {
			t.Fatal("Failed to create a simulation context.")
		}
		defer client.DestroyContext(handle, DestroyDescendants)

		// Could prove difficult to prove it is a cryptographically secure random.
		if *handle == ContextHandle([16]byte{0}) {
			t.Fatal("Incorrect simulation context handle.")
		}
	}
}

// When simulation is set to false, returns a default context handle.
// Else initializes a simulation context and returns its handle. To get simulation
// context handle, the DPE profile must support simulation context creation.
// Caller must ensure to destroy the non-default handle through DestroyContext after usage.
func getInitialContextHandle(d TestDPEInstance, c DPEClient, t *testing.T, simulation bool) *ContextHandle {
	var handle *ContextHandle
	var err error
	if simulation {
		if d.GetSupport().Simulation {
			handle, err = c.InitializeContext(InitIsSimulation)
			if err != nil {
				t.Fatal("The instance should be able to create a simulation context.")
			}
			if *handle == ContextHandle([16]byte{0}) {
				t.Fatal("Incorrect simulation context handle.")
			}
		} else {
			t.Fatal("[FATAL]:  DPE instance doesn't support simulation contexts.")
		}
	} else {
		//default context
		handle = &DefaultContextHandle
	}

	return handle
}
