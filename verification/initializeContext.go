// Licensed under the Apache-2.0 license

package verification

import (
	"errors"
	"log"
	"testing"
)

// This file is used to test the initialize context command.

func TestInitializeContext(d TestDPEInstance, t *testing.T) {
	for _, locality := range d.GetSupportedLocalities() {
		d.SetLocality(locality)
		testInitContext(d, t, false)
	}
}

func TestInitializeSimulation(d TestDPEInstance, t *testing.T) {
	for _, locality := range d.GetSupportedLocalities() {
		d.SetLocality(locality)
		testInitContext(d, t, true)
	}
}

func testInitContext(d TestDPEInstance, t *testing.T, simulation bool) {
	if d.HasPowerControl() {
		err := d.PowerOn()
		if err != nil {
			log.Fatal(err)
		}
		defer d.PowerOff()
	}

	profile, err := GetTransportProfile(d)
	if err != nil {
		t.Fatalf("Could not get profile: %v", err)
	}

	client, err := NewClient(d, profile)
	if err != nil {
		t.Fatalf("Could not initialize client: %v", err)
	}

	// Try to create the default context if isn't done automatically.
	if !d.GetSupport().AutoInit {
		handle, err := client.InitializeContext(InitIsDefault)
		if err != nil {
			t.Fatalf("Failed to initialize default context: %v", err)
		}
		if *handle != ContextHandle([16]byte{0}) {
			t.Fatal("Incorrect default context handle.")
		}
		defer client.DestroyContext(handle, DestroyDescendants)
	}

	// Try to initialize another default context.
	_, err = client.InitializeContext(InitIsDefault)
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
