// Licensed under the Apache-2.0 license

package verification

import (
	"errors"
	"testing"

	"github.com/chipsalliance/caliptra-dpe/verification/client"
)

// This file is used to test the initialize context command.

// TestInitializeContext tests calling InitializeContext
func TestInitializeContext(d client.TestDPEInstance, c client.DPEClient, t *testing.T) {
	for _, locality := range d.GetSupportedLocalities() {
		d.SetLocality(locality)
		testInitContext(d, c, t, false)
	}
}

// TestInitializeSimulation tests calling InitializeContext simulation mode
func TestInitializeSimulation(d client.TestDPEInstance, c client.DPEClient, t *testing.T) {
	for _, locality := range d.GetSupportedLocalities() {
		d.SetLocality(locality)
		testInitContext(d, c, t, true)
	}
}

func testInitContext(d client.TestDPEInstance, c client.DPEClient, t *testing.T, simulation bool) {
	// Try to create the default context if isn't done automatically.
	if !d.GetIsInitialized() {
		handle, err := c.InitializeContext(client.InitIsDefault)
		if err != nil {
			t.Fatalf("Failed to initialize default context: %v", err)
		}
		if *handle != client.ContextHandle([16]byte{0}) {
			t.Fatal("Incorrect default context handle.")
		}
		d.SetIsInitialized(true)
	}

	// Try to initialize another default context.
	_, err := c.InitializeContext(client.InitIsDefault)
	if err == nil {
		t.Fatal("The instance should return an error when trying to initialize another default context.")
	} else if !errors.Is(err, client.StatusArgumentNotSupported) {
		t.Fatalf("Incorrect error type. Should return %q, but returned %q", client.StatusArgumentNotSupported, err)
	}

	// Try to initialize a context that is neither default or simulation.
	_, err = c.InitializeContext(client.InitCtxFlags(0))
	if err == nil {
		t.Fatal("The instance should return an error when not default or simulation.")
	} else if !errors.Is(err, client.StatusInvalidArgument) {
		t.Fatalf("Incorrect error type. Should return %q, but returned %q", client.StatusInvalidArgument, err)
	}

	// TODO: test exhausting handles. This requires the ability to query how
	// many handles are currently in use.
	if simulation {
		handle, err := c.InitializeContext(client.InitIsSimulation)
		if err != nil {
			t.Fatal("Failed to create a simulation context.")
		}
		defer c.DestroyContext(handle)

		// Could prove difficult to prove it is a cryptographically secure random.
		if *handle == client.ContextHandle([16]byte{0}) {
			t.Fatal("Incorrect simulation context handle.")
		}
	}
}

// When simulation is set to false, returns a default context handle.
// Else initializes a simulation context and returns its handle. To get simulation
// context handle, the DPE profile must support simulation context creation.
// Caller must ensure to destroy the non-default handle through DestroyContext after usage.
func getInitialContextHandle(d client.TestDPEInstance, c client.DPEClient, t *testing.T, simulation bool) *client.ContextHandle {
	var handle *client.ContextHandle
	var err error
	if simulation {
		if d.GetSupport().Simulation {
			handle, err = c.InitializeContext(client.InitIsSimulation)
			if err != nil {
				t.Fatal("The instance should be able to create a simulation context.")
			}
			if *handle == client.ContextHandle([16]byte{0}) {
				t.Fatal("Incorrect simulation context handle.")
			}
		} else {
			t.Fatal("[FATAL]:  DPE instance doesn't support simulation contexts.")
		}
	} else {
		//default context
		handle = &client.DefaultContextHandle
	}

	return handle
}
